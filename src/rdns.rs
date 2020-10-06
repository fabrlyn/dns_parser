use crate::message::parse;
use crate::publisher;
use crate::publisher::Publisher;
use crate::resource_record::ResourceRecordData;
use net2::unix::UnixUdpBuilderExt;
use serde_json;
use std::net::Ipv4Addr;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MULTICAST_PORT: u16 = 5353;

pub fn net_mdns<P>(publisher: P)
where
  P: Publisher,
{
  let socket = net2::UdpBuilder::new_v4()
    .unwrap()
    .reuse_address(true)
    .unwrap()
    .reuse_port(true)
    .unwrap()
    .bind((ADDR_ANY, MULTICAST_PORT))
    .unwrap();

  socket.set_multicast_loop_v4(false).unwrap();
  socket
    .join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::new(0, 0, 0, 0))
    .unwrap();

  let mut buf: [u8; 65535] = [0; 65535];
  loop {
    let (amt, src) = socket.recv_from(&mut buf).unwrap();
    println!("length: {:?}", amt);
    println!("src: {:?}", src);
    let header = parse(&buf[..amt]);
    match header {
      Ok(message) => {
        print(&message);

        let publish_message = publisher::Message {
          source: src,
          header: message.header,
          queries: message.queries.iter().map(|q| q.name.clone()).collect(),
          answer: publisher::Answer {
            ip_v4: message
              .answers
              .iter()
              .filter_map(|a| match a.resource_record_data {
                ResourceRecordData::A(addr) => Some(addr.to_string()),
                _ => None,
              })
              .collect(),
          },
          additional: publisher::Additional {
            ip_v4: message
              .additional_records
              .iter()
              .filter_map(|a| match a.resource_record_data {
                ResourceRecordData::A(addr) => Some(addr.to_string()),
                _ => None,
              })
              .collect(),
          },
        };
        println!("publishing message");
        publisher
          .publish(
            "mdns.packet",
            &serde_json::to_string(&publish_message).unwrap(),
          )
          .unwrap();
      }
      Err(e) => {
        println!("Failed to parse header: {:?}", e);
        let data = &mut buf[..amt];
        for i in data {
          print!("{:?}, ", i);
        }
        println!("\n");
      }
    }

    //println!("received {} bytes from {:?}", amt, src);
  }
}

fn print(m: &crate::message::Message) {
  println!("HEADER");
  println!(" Query count        {:?}", m.header.question_count);
  println!(" Answer count:      {:?}", m.header.answer_count);
  println!(" Name server count: {:?}", m.header.name_server_count);
  println!(" Additional count:  {:?}", m.header.additional_count);
  println!(" - - -");

  println!("QUERIES");
  m.queries.iter().for_each(|q| println!(" {:?}", q.name));
  println!(" - - -");

  println!("ANSWERS");
  m.answers
    .iter()
    .for_each(|a| println!(" {:?} {}", a.resource_record_type, a.resource_record_data));
  println!(" - - -");

  println!("NAME SERVERS");
  m.name_servers
    .iter()
    .for_each(|n| println!(" {:?} {}", n.resource_record_type, n.resource_record_data));
  println!(" - - -");

  println!("ADDITIONAL");
  m.additional_records
    .iter()
    .for_each(|a| println!(" {:?} {}", a.resource_record_type, a.resource_record_data));
  println!(" - - -\n");
}
