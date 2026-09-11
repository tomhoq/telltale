//! Choosing a capture interface interactively when `live` gets no
//! `--interface`.
//!
//! The prompt goes to stderr so stdout stays clean for results, which may be
//! piped into something expecting JSON.

use std::io::{self, BufRead, IsTerminal, Write};

use pf_capture::sources::live;
use pf_capture::sources::InterfaceInfo;
use pf_core::{Error, Result};

/// List the interfaces, numbered, and ask for one. Returns its name as
/// [`pf_capture::LiveSource::open`] takes it.
pub fn interface() -> Result<String> {
    let interfaces = live::interfaces()?;
    if interfaces.is_empty() {
        return Err(Error::Capture("no capture interfaces found on this host".into()));
    }

    // Asking with nobody to answer would hang a script or eat its input.
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let names: Vec<String> = interfaces.iter().map(ToString::to_string).collect();
        return Err(Error::Capture(format!(
            "no --interface given and no terminal to ask on; pass one of: {}",
            names.join(", ")
        )));
    }

    let mut out = io::stderr().lock();
    writeln!(out, "Interfaces:")?;
    for (number, interface) in (1..).zip(&interfaces) {
        writeln!(out, "  {number:>2}) {}", row(interface))?;
    }

    let count = interfaces.len();
    let mut line = String::new();
    loop {
        write!(out, "Capture on which interface? [1-{count}]: ")?;
        out.flush()?;

        line.clear();
        if stdin.lock().read_line(&mut line)? == 0 {
            writeln!(out)?;
            return Err(Error::Capture("no interface chosen".into()));
        }

        match parse_choice(&line, count) {
            Some(index) => {
                let name = interfaces[index].name.clone();
                // The Windows names are long device paths nobody would type
                // from memory; show it once so it can be passed next time.
                writeln!(out, "Capturing on {name} (pass `-i {name}` to skip this prompt)")?;
                return Ok(name);
            }
            None => writeln!(out, "Enter a number from 1 to {count}.")?,
        }
    }
}

/// Description first when there is one: on Windows it is the readable part,
/// and the device path is only needed after the choice is made.
fn row(interface: &InterfaceInfo) -> String {
    let label = match interface.description.as_str() {
        "" => interface.name.as_str(),
        description => description,
    };
    if interface.addresses.is_empty() {
        return label.to_string();
    }
    let addresses: Vec<String> = interface.addresses.iter().map(ToString::to_string).collect();
    format!("{label}  [{}]", addresses.join(", "))
}

/// 1-based choice from the user to a 0-based index, or `None` if it is not
/// one of the listed numbers.
fn parse_choice(input: &str, count: usize) -> Option<usize> {
    let number: usize = input.trim().parse().ok()?;
    (1..=count).contains(&number).then(|| number - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_one_based_and_whitespace_is_ignored() {
        assert_eq!(parse_choice("1\n", 3), Some(0));
        assert_eq!(parse_choice("  3 \r\n", 3), Some(2));
    }

    #[test]
    fn anything_outside_the_list_is_rejected() {
        for input in ["0", "4", "-1", "", "eth0", "1.5"] {
            assert_eq!(parse_choice(input, 3), None, "{input:?}");
        }
    }
}
