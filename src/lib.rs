#[macro_use]
extern crate log;

mod authentication_logs;
mod cli;
pub mod config;
mod hashing;
mod persist;
mod style;
pub mod test_utils;

use multi_dispatcher::message::Message;
