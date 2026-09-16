//! Wires the pipeline together: source -> assembler -> dispatcher -> store -> output.
//!
//! Deliberately thin. Anything worth a unit test belongs in a library crate.

mod config;
mod pick;

use std::sync::Arc;
use std::thread;

use clap::{Parser, Subcommand, ValueEnum};
use pf_capture::sources::{HoneypotLogSource, LiveSource, PcapFileSource, TcpdumpSource};
use pf_capture::Source;
use pf_core::{Observation, Session};
use pf_dispatch::{Assembler, Dispatcher, Emitted, Job};
use pf_methods::Registry;
use pf_output::{render_json, render_line, render_text, InferenceConsumer};

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

    /// Analyse both directions of a session instead of just the traffic
    /// incoming from its initiator. Overrides `both-directions` in the config
    /// file, if set there.
    #[arg(long, global = true)]
    both_directions: bool,

    /// Log every observation as it comes off the source — endpoints,
    /// transport, payload size, and the raw TCP/IP signature fields `f0p`
    /// matches on, when the source can see them. Shorthand for `RUST_LOG=debug`
    /// that doesn't require knowing the env var; logs go to stderr, so they
    /// never mix with `--format json` on stdout.
    #[arg(long, global = true)]
    debug: bool,
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
    let cli = Cli::parse();

    // `--debug` is a shorthand for `RUST_LOG=debug`; either way logs go to
    // stderr so they never land in `--format json`'s stdout output.
    let filter = if cli.debug {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let mut config = match &cli.config {
        Some(path) => PipelineConfig::load(path)?,
        None => PipelineConfig::default(),
    };
    if cli.both_directions {
        config.both_directions = true;
    }
    let registry = Registry::load_dir(&config.manifest_dir)?;

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
    // pf-dispatch is generic over "a thing that turns a session into
    // evidence" — the registry, and the direction policy it needs to apply
    // that, are pf-methods' concern, so they are closed over here rather than
    // threaded through the dispatcher's own API.
    let registry = Arc::new(registry);
    let both_directions = config.both_directions;
    let analyze = {
        let registry = Arc::clone(&registry);
        move |session: &Session, is_final: bool| registry.analyze(session, is_final, both_directions)
    };
    let (dispatcher, results) = Dispatcher::spawn(config.workers, analyze);
    let mut assembler = Assembler::new(config.session_timeout());

    // A session finishes — times out, or the source ends — the moment its
    // own inactivity window closes, which for `live`/`tcpdump` can be long
    // before the run itself does; those sources never end on their own at
    // all. Consuming results here, off a dedicated thread, as they arrive is
    // what makes that visible: without it nothing prints until the capture
    // loop below exits, which for those sources never happens, so it would
    // look like nothing was ever being classified even though the dispatcher
    // is scoring sessions the whole time.
    let print_incrementally = matches!(format, Format::Text);
    let consumer = thread::spawn(move || {
        InferenceConsumer::consume_streaming(results, |evidence, store| {
            if print_incrementally {
                if let Some(profile) = store.get(&evidence.subject) {
                    println!("{}", render_line(&evidence.subject, profile));
                }
            }
        })
    });

    while let Some(observation) = source.next_observation()? {
        let now = observation.at;
        log_observation(&observation);

        match assembler.ingest(observation) {
            Emitted::Opened(key) | Emitted::Updated(key) => {
                // In streaming mode every new observation is a chance to refine
                // the verdict; in batch mode we wait for the session to finish.
                if config.output == OutputMode::InferenceTime {
                    if let Some(session) = assembler.get(&key) {
                        submit(&dispatcher, session.clone(), false);
                    }
                }
            }
            Emitted::Finished(session) => submit(&dispatcher, session, true),
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

    // Closing the queue lets the workers finish and the result channel close,
    // which is what lets the consumer thread's `for batch in results` loop
    // end and hand back the final store.
    dispatcher.shutdown();
    let store = consumer.join().expect("result consumer thread should not panic");

    match format {
        // Already streamed above, one line per update as it happened; this is
        // the final tally, grouped and sorted, once the run is actually over.
        Format::Text => print!("{}", render_text(&store)),
        Format::Json => print!("{}", render_json(&store)),
    }
    Ok(())
}

fn submit(dispatcher: &Dispatcher, session: Session, is_final: bool) {
    dispatcher.submit(Job { session, is_final });
}

/// One line per observation as it comes off the source, at `--debug`/
/// `RUST_LOG=debug`. The TCP fields are the exact signal `f0p` matches
/// against, which is what makes this useful for "why didn't that session
/// fingerprint the way I expected" rather than just "traffic is flowing".
fn log_observation(observation: &Observation) {
    match &observation.tcp {
        Some(tcp) => tracing::debug!(
            source = %observation.source.addr,
            source_port = observation.source.port,
            destination = %observation.destination.addr,
            destination_port = observation.destination.port,
            transport = ?observation.transport,
            stage_hint = ?observation.stage_hint,
            payload_len = observation.payload.len(),
            ttl = tcp.ttl,
            df = tcp.df,
            window = tcp.window,
            mss = ?tcp.mss,
            window_scale = ?tcp.window_scale,
            sack_permitted = tcp.sack_permitted,
            timestamp = tcp.timestamp,
            options = ?tcp.option_order,
            "packet received"
        ),
        None => tracing::debug!(
            source = %observation.source.addr,
            source_port = observation.source.port,
            destination = %observation.destination.addr,
            destination_port = observation.destination.port,
            transport = ?observation.transport,
            stage_hint = ?observation.stage_hint,
            payload_len = observation.payload.len(),
            "packet received"
        ),
    }
}
