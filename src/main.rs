mod app;
mod cmd_parser;
mod setup;

use app::run;
use cmd_parser::{Mode, parse_mode};
use setup::setup;

fn main() {
    match parse_mode() {
        Mode::Setup => setup(),
        Mode::Run => run(),
    }
}
