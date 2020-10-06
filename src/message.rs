use crate::header::{parse_header, Header};
use crate::query::{parse_queries, Query};
use crate::resource_record::{parse_resource_records, ResourceRecord};
use crate::shared::Label;
use crate::shared::ParseError;
/*
https://justanapplication.wordpress.com/category/dns/dns-resource-records/dns-srv-record/

https://tools.ietf.org/html/rfc5395
https://tools.ietf.org/html/rfc2136
https://tools.ietf.org/html/rfc6195

https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

https://flylib.com/books/en/3.223.1.151/1/

https://tools.ietf.org/html/rfc1035 -> 4.1.1
*/

#[derive(Debug)]
pub struct Message {
  pub header: Header,
  pub queries: Vec<Query>,
  pub answers: Vec<ResourceRecord>,
  pub name_servers: Vec<ResourceRecord>,
  pub additional_records: Vec<ResourceRecord>,
}

fn parse_additional_resource_records(
  label_store: &mut Vec<Label>,
  offset: usize,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(label_store, offset, header.additional_count, data)
}

fn parse_name_servers(
  label_store: &mut Vec<Label>,
  offset: usize,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(label_store, offset, header.name_server_count, data)
}

fn parse_answers(
  label_store: &mut Vec<Label>,
  offset: usize,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(label_store, offset, header.answer_count, data)
}

pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
  let header = parse_header(data)?;

  let offset = 12;

  let mut label_store = vec![];

  let queries = parse_queries(&mut label_store, offset, &header, data)?;
  let queries_length = queries.iter().fold(offset, |sum, q| sum + q.size());

  let answers = parse_answers(&mut label_store, queries_length, &header, data)?;
  let answers_length = answers.iter().fold(queries_length, |sum, a| sum + a.size());

  let name_servers = parse_name_servers(&mut label_store, answers_length, &header, data)?;
  let name_server_resources_length = name_servers
    .iter()
    .fold(answers_length, |sum, r| sum + r.size());

  let additional_records = parse_additional_resource_records(
    &mut label_store,
    name_server_resources_length,
    &header,
    data,
  )?;

  Ok(Message {
    header,
    queries,
    answers,
    name_servers,
    additional_records,
  })
}

mod test {
  #[test]
  fn test_overflowing_packet() {
    let data = [
      0, 0, 132, 0, 0, 0, 0, 6, 0, 0, 0, 1, 9, 95, 115, 101, 114, 118, 105, 99, 101, 115, 7, 95,
      100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1,
      0, 0, 17, 148, 0, 23, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111, 110, 45, 108, 105, 110,
      107, 4, 95, 116, 99, 112, 192, 35, 4, 99, 111, 110, 102, 12, 95, 100, 101, 118, 105, 99, 101,
      45, 105, 110, 102, 111, 192, 68, 0, 16, 0, 1, 0, 0, 17, 148, 0, 14, 13, 109, 111, 100, 101,
      108, 61, 74, 49, 48, 53, 97, 65, 80, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0, 17, 14, 95, 109,
      101, 100, 105, 97, 114, 101, 109, 111, 116, 101, 116, 118, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 11, 8, 95, 97, 105, 114, 112, 108, 97, 121, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 8, 5, 95, 114, 97, 111, 112, 192, 68, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0,
      15, 12, 95, 115, 108, 101, 101, 112, 45, 112, 114, 111, 120, 121, 192, 30, 0, 0, 41, 5, 160,
      0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 38, 144, 221, 93, 181, 149, 101, 144, 221, 93, 172, 40,
      91,
    ];

    let something = &data[68..];
    println!("something: {:?}", something);

    let result = super::parse(&data);
    println!("Result: {:?}", result);
  }

  #[test]
  fn another_packet() {
    let data = [
      0, 0, 132, 0, 0, 0, 0, 6, 0, 0, 0, 1, 9, 95, 115, 101, 114, 118, 105, 99, 101, 115, 7, 95,
      100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1,
      0, 0, 17, 148, 0, 23, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111, 110, 45, 108, 105, 110,
      107, 4, 95, 116, 99, 112, 192, 35, 4, 99, 111, 110, 102, 12, 95, 100, 101, 118, 105, 99, 101,
      45, 105, 110, 102, 111, 192, 68, 0, 16, 0, 1, 0, 0, 17, 148, 0, 14, 13, 109, 111, 100, 101,
      108, 61, 74, 49, 48, 53, 97, 65, 80, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0, 17, 14, 95, 109,
      101, 100, 105, 97, 114, 101, 109, 111, 116, 101, 116, 118, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 11, 8, 95, 97, 105, 114, 112, 108, 97, 121, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 8, 5, 95, 114, 97, 111, 112, 192, 68, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0,
      15, 12, 95, 115, 108, 101, 101, 112, 45, 112, 114, 111, 120, 121, 192, 30, 0, 0, 41, 5, 160,
      0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 118, 144, 221, 93, 181, 149, 101, 144, 221, 93, 172,
      40, 91,
    ];

    data.iter().for_each(|d| {
      print!("{:X?} ", d);
    });
    println!("");
  }

  #[test]
  fn test_broke_it() {
    let data: Vec<u8> = vec![
      0, 0, 132, 0, 0, 0, 0, 8, 0, 0, 0, 3, 9, 95, 115, 101, 114, 118, 105, 99, 101, 115, 7, 95,
      100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1,
      0, 0, 17, 148, 0, 23, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111, 110, 45, 108, 105, 110,
      107, 4, 95, 116, 99, 112, 192, 35, 4, 99, 111, 110, 102, 12, 95, 100, 101, 118, 105, 99, 101,
      45, 105, 110, 102, 111, 192, 68, 0, 16, 0, 1, 0, 0, 17, 148, 0, 14, 13, 109, 111, 100, 101,
      108, 61, 74, 49, 48, 53, 97, 65, 80, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0, 17, 14, 95, 109,
      101, 100, 105, 97, 114, 101, 109, 111, 116, 101, 116, 118, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 11, 8, 95, 97, 105, 114, 112, 108, 97, 121, 192, 68, 192, 12, 0, 12, 0, 1, 0,
      0, 17, 148, 0, 8, 5, 95, 114, 97, 111, 112, 192, 68, 192, 12, 0, 12, 0, 1, 0, 0, 17, 148, 0,
      15, 12, 95, 115, 108, 101, 101, 112, 45, 112, 114, 111, 120, 121, 192, 30, 1, 51, 1, 48, 1,
      56, 1, 70, 1, 50, 1, 70, 1, 69, 1, 67, 1, 70, 1, 48, 1, 52, 1, 66, 1, 48, 1, 52, 1, 48, 1,
      48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1, 48, 1,
      48, 1, 56, 1, 69, 1, 70, 3, 105, 112, 54, 4, 97, 114, 112, 97, 0, 0, 12, 128, 1, 0, 0, 0,
      120, 0, 7, 4, 99, 111, 110, 102, 192, 35, 3, 49, 51, 54, 1, 49, 3, 49, 54, 56, 3, 49, 57, 50,
      7, 105, 110, 45, 97, 100, 100, 114, 193, 30, 0, 12, 128, 1, 0, 0, 0, 120, 0, 2, 193, 46, 192,
      218, 0, 47, 128, 1, 0, 0, 0, 120, 0, 6, 192, 218, 0, 2, 0, 8, 193, 53, 0, 47, 128, 1, 0, 0,
      0, 120, 0, 6, 193, 53, 0, 2, 0, 8, 0, 0, 41, 5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0,
      81, 144, 221, 93, 181, 149, 101, 144, 221, 93, 172, 40, 91,
    ];

    let dump = "
0000   00 00 84 00 00 00 00 08 00 00 00 03 09 5f 73 65
0010   72 76 69 63 65 73 07 5f 64 6e 73 2d 73 64 04 5f
0020   75 64 70 05 6c 6f 63 61 6c 00 00 0c 00 01 00 00
0030   11 94 00 17 0f 5f 63 6f 6d 70 61 6e 69 6f 6e 2d
0040   6c 69 6e 6b 04 5f 74 63 70 c0 23 04 63 6f 6e 66
0050   0c 5f 64 65 76 69 63 65 2d 69 6e 66 6f c0 44 00
0060   10 00 01 00 00 11 94 00 0e 0d 6d 6f 64 65 6c 3d
0070   4a 31 30 35 61 41 50 c0 0c 00 0c 00 01 00 00 11
0080   94 00 11 0e 5f 6d 65 64 69 61 72 65 6d 6f 74 65
0090   74 76 c0 44 c0 0c 00 0c 00 01 00 00 11 94 00 0b
00a0   08 5f 61 69 72 70 6c 61 79 c0 44 c0 0c 00 0c 00
00b0   01 00 00 11 94 00 08 05 5f 72 61 6f 70 c0 44 c0
00c0   0c 00 0c 00 01 00 00 11 94 00 0f 0c 5f 73 6c 65
00d0   65 70 2d 70 72 6f 78 79 c0 1e 01 33 01 30 01 38
00e0   01 46 01 32 01 46 01 45 01 43 01 46 01 30 01 34
00f0   01 42 01 30 01 34 01 30 01 30 01 30 01 30 01 30
0100   01 30 01 30 01 30 01 30 01 30 01 30 01 30 01 30
0110   01 30 01 30 01 38 01 45 01 46 03 69 70 36 04 61
0120   72 70 61 00 00 0c 80 01 00 00 00 78 00 07 04 63
0130   6f 6e 66 c0 23 03 31 33 36 01 31 03 31 36 38 03
0140   31 39 32 07 69 6e 2d 61 64 64 72 c1 1e 00 0c 80
0150   01 00 00 00 78 00 02 c1 2e c0 da 00 2f 80 01 00
0160   00 00 78 00 06 c0 da 00 02 00 08 c1 35 00 2f 80
0170   01 00 00 00 78 00 06 c1 35 00 02 00 08 00 00 29
0180   05 a0 00 00 11 94 00 12 00 04 00 0e 00 51 90 dd
0190   5d b5 95 65 90 dd 5d ac 28 5b
"
    .to_owned();
    let dump_vec = crate::hex::from_wire_shark(dump);
    assert_eq!(dump_vec, data);

    dump_vec
      .iter()
      .map(|c| std::str::from_utf8(&[*c]).unwrap_or(" ").to_owned())
      .filter(|c| *c != " ".to_owned())
      .map(|c| if c == "\n" { " ".to_owned() } else { c })
      .for_each(|c| print!("{}", c));
    println!("");

    /*
    Frame 115: 452 bytes on wire (3616 bits), 452 bytes captured (3616 bits) on interface en0, id 0
    Ethernet II, Src: Apple_ac:28:5b (90:dd:5d:ac:28:5b), Dst: IPv4mcast_fb (01:00:5e:00:00:fb)
    Internet Protocol Version 4, Src: 192.168.1.136, Dst: 224.0.0.251
    User Datagram Protocol, Src Port: 5353, Dst Port: 5353
    Multicast Domain Name System (response)
        Transaction ID: 0x0000
        Flags: 0x8400 Standard query response, No error
            1... .... .... .... = Response: Message is a response
            .000 0... .... .... = Opcode: Standard query (0)
            .... .1.. .... .... = Authoritative: Server is an authority for domain
            .... ..0. .... .... = Truncated: Message is not truncated
            .... ...0 .... .... = Recursion desired: Don't do query recursively
            .... .... 0... .... = Recursion available: Server can't do recursive queries
            .... .... .0.. .... = Z: reserved (0)
            .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
            .... .... ...0 .... = Non-authenticated data: Unacceptable
            .... .... .... 0000 = Reply code: No error (0)
        Questions: 0
        Answer RRs: 8
        Authority RRs: 0
        Additional RRs: 3
        Answers
            _services._dns-sd._udp.local: type PTR, class IN, _companion-link._tcp.local
                Name: _services._dns-sd._udp.local
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 23
                Domain Name: _companion-link._tcp.local
            conf._device-info._tcp.local: type TXT, class IN
                Name: conf._device-info._tcp.local
                Type: TXT (Text strings) (16)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 14
                TXT Length: 13
                TXT: model=J105aAP
            _services._dns-sd._udp.local: type PTR, class IN, _mediaremotetv._tcp.local
                Name: _services._dns-sd._udp.local
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 17
                Domain Name: _mediaremotetv._tcp.local
            _services._dns-sd._udp.local: type PTR, class IN, _airplay._tcp.local
                Name: _services._dns-sd._udp.local
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 11
                Domain Name: _airplay._tcp.local
            _services._dns-sd._udp.local: type PTR, class IN, _raop._tcp.local
                Name: _services._dns-sd._udp.local
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 8
                Domain Name: _raop._tcp.local
            _services._dns-sd._udp.local: type PTR, class IN, _sleep-proxy._udp.local
                Name: _services._dns-sd._udp.local
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                0... .... .... .... = Cache flush: False
                Time to live: 4500 (1 hour, 15 minutes)
                Data length: 15
                Domain Name: _sleep-proxy._udp.local
            3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa: type PTR, class IN, cache flush, conf.local
                Name: 3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                1... .... .... .... = Cache flush: True
                Time to live: 120 (2 minutes)
                Data length: 7
                Domain Name: conf.local
            136.1.168.192.in-addr.arpa: type PTR, class IN, cache flush, conf.local
                Name: 136.1.168.192.in-addr.arpa
                Type: PTR (domain name PoinTeR) (12)
                .000 0000 0000 0001 = Class: IN (0x0001)
                1... .... .... .... = Cache flush: True
                Time to live: 120 (2 minutes)
                Data length: 2
                Domain Name: conf.local
        Additional records
            3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa: type NSEC, class IN, cache flush, next domain name 3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
                Name: 3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
                Type: NSEC (Next Secure) (47)
                .000 0000 0000 0001 = Class: IN (0x0001)
                1... .... .... .... = Cache flush: True
                Time to live: 120 (2 minutes)
                Data length: 6
                Next Domain Name: 3.0.8.F.2.F.E.C.F.0.4.B.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa
                RR type in bit map: PTR (domain name PoinTeR)
            136.1.168.192.in-addr.arpa: type NSEC, class IN, cache flush, next domain name 136.1.168.192.in-addr.arpa
                Name: 136.1.168.192.in-addr.arpa
                Type: NSEC (Next Secure) (47)
                .000 0000 0000 0001 = Class: IN (0x0001)
                1... .... .... .... = Cache flush: True
                Time to live: 120 (2 minutes)
                Data length: 6
                Next Domain Name: 136.1.168.192.in-addr.arpa
                RR type in bit map: PTR (domain name PoinTeR)
            <Root>: type OPT
                Name: <Root>
                Type: OPT (41)
                .000 0101 1010 0000 = UDP payload size: 0x05a0
                0... .... .... .... = Cache flush: False
                Higher bits in extended RCODE: 0x00
                EDNS0 version: 0
                Z: 0x1194
                    0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                    .001 0001 1001 0100 = Reserved: 0x1194
                Data length: 18
                Option: Owner (reserved)
                    Option Code: Owner (reserved) (4)
                    Option Length: 14
                    Option Data: 005190dd5db5956590dd5dac285b
        [Request In: 113]
        [Time: 0.001279000 seconds]


        */

    println!("{:?}", dump_vec);
    let result = super::parse(&dump_vec);
    println!("result: {:?}", result);
  }
}
