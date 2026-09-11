//! Wires the pipeline together: source -> assembler -> dispatcher -> store -> output.
//!
//! Deliberately thin. Anything worth a unit test belongs in a library crate.

mod config;
mod pick;

use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use pf_capture::sources::{HoneypotLogSource, LiveSource, PcapFileSource, TcpdumpSource};
use pf_capture::Source;
use pf_core::Session;
use pf_dispatch::{Assembler, Dispatcher, Emitted, Job};
use pf_methods::Registry;
use pf_output::{render_json, render_text, BatchConsumer};

use crate::config::{OutputMode, PipelineConfig};

#[derive(Parser)]
#[command(
    name = "telltale-pf",
    version,
    about = "Passive fingerprinting of intruder characteristics (OS, client stack, etc.)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Pipeline configuration. Defaults are used if omitted.
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
}

#[derive(Subcommand)]
enum Command {
    /// Read from a live interface.
    Live {
        /// Interface to capture on. Omit to choose from a numbered list.
        #[arg(short, long)]
        interface: Option<String>,
        /// BPF filter applied in the kernel.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Replay a capture file.
    Replay {
        #[arg(short, long)]
        path: std::path::PathBuf,
    },
    /// Read tcpdump output.
    Tcpdump {
        #[arg(long, default_value = "tcpdump -i any -w -")]
        command: String,
    },
    /// Ingest a honeypot log.
    Honeypot {
        #[arg(short, long)]
        path: std::path::PathBuf,
        /// Which honeypot wrote it.
        #[arg(long)]
        format: String,
    },
    /// List the methods the current configuration would run.
    Methods,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> pf_core::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = match &cli.config {
        Some(path) => PipelineConfig::load(path)?,
        None => PipelineConfig::default(),
    };
    let registry = Registry::load_dir(&config.manifest_dir)?; // reads every yaml file in path

    if let Command::Methods = cli.command {
        for name in registry.names() {
            println!("{name}");
        }
        return Ok(());
    }

    let mut source: Box<dyn Source> = match cli.command {
        Command::Live { interface, filter } => {
            let interface = match interface {
                Some(interface) => interface,
                None => pick::interface()?,
            };
            Box::new(LiveSource::open(interface, filter)?)
        }
        Command::Replay { path } => Box::new(PcapFileSource::open(path)?),
        Command::Tcpdump { command } => Box::new(TcpdumpSource::spawn(command)?),
        Command::Honeypot { path, format } => Box::new(HoneypotLogSource::open(path, format)?),
        Command::Methods => unreachable!("handled above"),
    };

    tracing::info!(source = %source.describe(), mode = ?config.output, "starting");
    run(source.as_mut(), registry, &config, cli.format)
}

fn run(
    source: &mut dyn Source,
    registry: Registry,
    config: &PipelineConfig,
    format: Format,
) -> pf_core::Result<()> {
    let streaming = config.output == OutputMode::InferenceTime;
    let every_observation = registry.wants_every_observation();
    let (dispatcher, results) = Dispatcher::spawn(Arc::new(registry), config.workers);
    let mut assembler = Assembler::new(config.session_timeout());

    while let Some(observation) = source.next_observation()? { // blocked until next observation is available
        let now = observation.at;

        // In streaming mode, a session is re-analysed whenever its answer can
        // change: when it reaches a stage that opens some method's gate, or on
        // every packet if a method asked for that. Each pass is the whole
        // answer so far and replaces the previous one. In batch mode we wait
        // for the session to finish.
        let provisional_pass = match assembler.ingest(observation) {
            Emitted::Opened(key) | Emitted::Advanced(key) => streaming.then_some(key),
            Emitted::Updated(key) => (streaming && every_observation).then_some(key),
            Emitted::Finished(session) => {
                submit(&dispatcher, session, true);
                None
            }
        };
        if let Some(session) = provisional_pass.and_then(|key| assembler.get(&key)) {
            submit(&dispatcher, session.clone(), false);
        }

        // The timeout is what stops a method that is waiting on a stage from
        // pinning a session open forever.
        for session in assembler.expire(now) {
            submit(&dispatcher, session, true);
        }
    }

    for session in assembler.drain() {
        submit(&dispatcher, session, true);
    }

    // Closing the queue lets the workers finish and the result channel close.
    dispatcher.shutdown();

    // Consume results via pf_output
    let store = BatchConsumer::consume(results);

    let out = match format {
        Format::Text => render_text(&store),
        Format::Json => render_json(&store),
    };
    print!("{out}");
    Ok(())
}

fn submit(dispatcher: &Dispatcher, session: Session, is_final: bool) {
    dispatcher.submit(Job { session, is_final });
}
