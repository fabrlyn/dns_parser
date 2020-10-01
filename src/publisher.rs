use crate::header::Header;
use nats::Connection;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
  pub source: std::net::SocketAddr,
  pub header: Header,
  pub queries: Vec<String>,
  pub answer: Answer,
  pub additional: Additional,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Answer {
  pub ip_v4: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Additional {
  pub ip_v4: Vec<String>,
}

pub trait Publisher {
  fn publish(&self, subject: &str, data: &str) -> io::Result<()>;
}

pub struct NatsPublisher {
  connection: Connection,
}

impl NatsPublisher {
  pub fn new() -> io::Result<NatsPublisher> {
    Ok(NatsPublisher {
      connection: nats::connect("localhost")?,
    })
  }
}

impl Publisher for NatsPublisher {
  fn publish(&self, subject: &str, data: &str) -> io::Result<()> {
    self.connection.publish(subject, data)
  }
}

pub struct TerminalPublisher {}

impl Publisher for TerminalPublisher {
  fn publish(&self, subject: &str, data: &str) -> io::Result<()> {
    println!("{:?} => {:?}", subject, data);
    Ok(())
  }
}
