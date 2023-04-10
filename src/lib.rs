#[macro_use]
extern crate log;

mod authentication_logs;
mod cli;
pub mod config;
pub mod entropy;
mod hashing;
mod persist;
mod style;
pub mod test_utils;

use multi_dispatcher::message::Message;
