//! Wires the pipeline together: source -> engine (sessions, triggers, workers)
//! -> result stream -> output.
//!
//! Deliberately thin. Anything worth a unit test belongs in a library crate.

mod config;
mod pick;

use std::io::{self, Write};
use std::sync::Arc;
use std::thread;

use clap::{Parser, Subcommand, ValueEnum};
use pf_capture::sources::{HoneypotLogSource, LiveSource, PcapFileSource, TcpdumpSource};
use pf_capture::Source;
use pf_dispatch::Engine;
use pf_methods::Registry;
use pf_output::consumer;
use pf_output::{render_result_json, render_result_text, render_session_json, render_session_text};

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
        for method in registry.iter() {
            let manifest = method.manifest();
            let triggers: Vec<String> = manifest
                .triggers
                .iter()
                .map(|t| format!("{t:?}"))
                .collect();
            println!("{:<12} {:?}  {}", manifest.name, manifest.layer, triggers.join(", "));
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
    let (mut engine, updates) =
        Engine::new(Arc::new(registry), config.session_timeout(), config.workers);

    // Output runs beside capture, so a session shows up as soon as it is
    // finalized (batch) or a result as soon as it is appended (inference),
    // rather than all at the end.
    let mode = config.output;
    let printer = thread::spawn(move || {
        let mut out = io::stdout().lock();
        let shown = match mode {
            OutputMode::PerSession => consumer::batch(updates, |session| {
                let text = match format {
                    Format::Text => render_session_text(session),
                    Format::Json => render_session_json(session),
                };
                let _ = out.write_all(text.as_bytes());
            }),
            OutputMode::InferenceTime => consumer::inference(updates, |session, initiator, entry| {
                let text = match format {
                    Format::Text => render_result_text(session, initiator, entry),
                    Format::Json => render_result_json(session, initiator, entry),
                };
                let _ = out.write_all(text.as_bytes());
            }),
        };
        if shown == 0 {
            if let Format::Text = format {
                let _ = writeln!(out, "nothing to report");
            }
        }
    });

    // blocked until next observation is available
    let captured = (|| {
        while let Some(observation) = source.next_observation()? {
            engine.ingest(observation);
        }
        Ok(())
    })();

    // Even when the source failed part way, finish what was captured: every
    // open session is ended and published before the output thread stops.
    engine.finish();
    printer.join().expect("output thread panicked");
    captured
}
