use crate::header::{parse_header, Header};
use crate::query::{parse_queries_v2, QueryV2};
use crate::resource_record::{parse_resource_records_v2, ResourceRecordV2};
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
pub struct MessageV2<'a> {
  pub header: Header,
  pub queries: Vec<QueryV2<'a>>,
  pub answers: Vec<ResourceRecordV2<'a>>,
  pub name_servers: Vec<ResourceRecordV2<'a>>,
  pub additional_records: Vec<ResourceRecordV2<'a>>,
}

fn parse_additional_resource_records_v2<'a>(
  offset: usize,
  header: &Header,
  data: &'a [u8],
) -> Result<Vec<ResourceRecordV2<'a>>, ParseError> {
  parse_resource_records_v2(offset, header.ar_count, data)
}

fn parse_name_servers_v2<'a>(
  offset: usize,
  header: &Header,
  data: &'a [u8],
) -> Result<Vec<ResourceRecordV2<'a>>, ParseError> {
  parse_resource_records_v2(offset, header.ns_count, data)
}

fn parse_answers_v2<'a>(
  offset: usize,
  header: &Header,
  data: &'a [u8],
) -> Result<Vec<ResourceRecordV2<'a>>, ParseError> {
  parse_resource_records_v2(offset, header.an_count, data)
}

pub fn parse_v2(data: &[u8]) -> Result<MessageV2, ParseError> {
  let header = parse_header(data)?;

  let offset = 12;

  let queries = parse_queries_v2(offset, &header, data)?;
  let queries_length = queries.iter().fold(offset, |sum, q| sum + q.size());

  let answers = parse_answers_v2(queries_length, &header, data)?;
  let answers_length = answers.iter().fold(queries_length, |sum, a| sum + a.size());

  let name_servers = parse_name_servers_v2(answers_length, &header, data)?;
  let name_server_resources_length = name_servers
    .iter()
    .fold(answers_length, |sum, r| sum + r.size());

  let additional_records =
    parse_additional_resource_records_v2(name_server_resources_length, &header, data)?;

  Ok(MessageV2 {
    header,
    queries,
    answers,
    name_servers,
    additional_records,
  })
}
