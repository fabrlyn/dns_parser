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
  fn test_esp_packet() {
    let data = &[
      0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 2, 10, 69, 83, 80, 95, 56, 48, 57, 57, 57, 50, 8, 95, 102,
      97, 98, 114, 108, 121, 110, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 255, 128,
      1, 192, 48, 0, 12, 0, 1, 0, 0, 17, 148, 0, 2, 192, 79, 192, 79, 0, 33, 0, 1, 0, 0, 17, 148,
      0, 8, 0, 0, 0, 0, 19, 136, 192, 129, 192, 79, 0, 16, 0, 1, 0, 0, 17, 148, 0, 0, 192, 129, 0,
      1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 43,
    ];

    let result = super::parse(data);
  }
}
