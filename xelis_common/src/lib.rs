pub mod crypto;
pub mod serializer;
pub mod transaction;
pub mod block;
pub mod account;
pub mod api;

pub mod utils;
pub mod config;
pub mod immutable;
pub mod difficulty;
pub mod network;
pub mod asset;
pub mod context;
pub mod queue;
pub mod varuint;
pub mod time;

#[cfg(feature = "json_rpc")]
pub mod json_rpc;

#[cfg(feature = "prompt")]
pub mod prompt;

#[cfg(feature = "rpc_server")]
pub mod rpc_server;

#[cfg(feature = "clap")]
// If clap feature is enabled, build the correct style for CLI
pub fn get_cli_styles() -> clap::builder::Styles {
    use clap::builder::styling::*;

    clap::builder::Styles::styled()
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .header(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .literal(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .placeholder(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
}