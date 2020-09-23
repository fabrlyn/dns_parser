use crate::header::{parse_header, Header};
use crate::query::{parse_queries, Query};
use crate::resource_record::{parse_resource_records, ResourceRecord};
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

pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
  let header = parse_header(data)?;

  let offset = 12;

  let queries = parse_queries(offset, &header, &data[offset as usize..])?;
  let queries_length = queries.iter().fold(offset, |sum, q| sum + q.size() as u16);

  let answers = parse_answers(queries_length, &header, &data[queries_length as usize..])?;
  let answers_length = answers
    .iter()
    .fold(queries_length, |sum, a| sum + a.size() as u16);

  let name_servers = parse_name_servers(answers_length, &header, &data[answers_length as usize..])?;
  let name_server_resources_length = name_servers
    .iter()
    .fold(answers_length, |sum, r| sum + r.size() as u16);

  let additional_records = parse_additional_resource_records(
    name_server_resources_length,
    &header,
    &data[name_server_resources_length as usize..],
  )?;

  Ok(Message {
    header,
    queries,
    answers,
    name_servers,
    additional_records,
  })
}

fn parse_additional_resource_records(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.ar_count, data)
}

fn parse_name_servers(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.ns_count, data)
}

fn parse_answers(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.an_count, data)
}
