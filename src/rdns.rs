use crate::message::parse_v2;
use net2::unix::UnixUdpBuilderExt;
use std::net::Ipv4Addr;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MULTICAST_PORT: u16 = 5353;

pub fn net_mdns() {
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

  let mut buf = [0u8; 65535];
  loop {
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let header = parse_v2(&buf[0..amt]);
    match header {
      Ok(message) => {
        println!("header: {:?}", message.header);
        println!("queries: {:?}", message.queries);
        println!("answers: {:?}", message.answers);
        println!("name_servers: {:?}", message.name_servers);
        println!("additional: {:?}", message.additional_records);
      }
      Err(e) => {
        println!("Failed to parse header: {:?}", e);
      }
    }

    //println!("received {} bytes from {:?}", amt, src);
    let data = &mut buf[..amt];
    for i in data {
      print!("{:?}, ", i);
    }
    println!("\n");
  }
}

/*
Message ID: 2
QoR: Response(1)
*/
