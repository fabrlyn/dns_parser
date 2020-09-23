use crate::header::Header;
use crate::shared::{
  parse_class, parse_name, parse_name_v2, parse_type, Class, Label, LabelV2, ParseError, Type,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum QType {
  Type(Type),
  AXFR,
  MAILB,
  MAILA,
  Any,
}

#[derive(Debug, PartialEq, Eq)]
enum QClass {
  Any,
  Class(Class),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Query {
  values: Vec<Label>,
  q_response_type: QuestionResponseType,
  q_type: QType,
  q_class: QClass,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueryV2<'a> {
  values: Vec<LabelV2<'a>>,
  q_response_type: QuestionResponseType,
  q_type: QType,
  q_class: QClass,
}

#[derive(PartialEq, Eq, Debug)]
enum QuestionResponseType {
  QU,
  QM,
}

impl<'a> QueryV2<'a> {
  pub fn size(&self) -> usize {
    let q_type_size = 2;
    let q_class_size = 2;

    self
      .values
      .iter()
      .fold(q_type_size + q_class_size, |sum, s| sum + s.size())
  }
}

impl Query {
  pub fn size(&self) -> usize {
    let q_type_size = 2;
    let q_class_size = 2;

    self
      .values
      .iter()
      .fold(q_type_size + q_class_size, |sum, s| sum + s.size())
  }
}

fn parse_query(current_offset: u16, data: &[u8]) -> Result<Query, ParseError> {
  let values = parse_name(current_offset, data)?;
  let offset = values.iter().fold(0, |sum, l| sum + l.size());

  if data.len() < offset + 4 {
    return Err(ParseError::QueryError(
      "Data not long enough for query".to_owned(),
    ));
  }

  let mut q_type_data: [u8; 2] = [0; 2];
  q_type_data.copy_from_slice(&data[offset..offset + 2]);
  let (q_response_type, q_type) = parse_q_type(q_type_data);

  let mut q_class_data: [u8; 2] = [0; 2];
  q_class_data.copy_from_slice(&data[offset + 2..offset + 4]);
  let q_class = parse_q_class(q_class_data);

  Ok(Query {
    values,
    q_response_type,
    q_type,
    q_class,
  })
}

fn parse_query_v2(offset: usize, data: &[u8]) -> Result<QueryV2, ParseError> {
  let values = parse_name_v2(offset, data)?;
  let offset = values.iter().fold(0, |sum, l| sum + l.size());

  if data.len() < offset + 4 {
    return Err(ParseError::QueryError(
      "Data not long enough for query".to_owned(),
    ));
  }

  let mut q_type_data: [u8; 2] = [0; 2];
  q_type_data.copy_from_slice(&data[offset..offset + 2]);
  let (q_response_type, q_type) = parse_q_type(q_type_data);

  let mut q_class_data: [u8; 2] = [0; 2];
  q_class_data.copy_from_slice(&data[offset + 2..offset + 4]);
  let q_class = parse_q_class(q_class_data);

  Ok(QueryV2 {
    values,
    q_response_type,
    q_type,
    q_class,
  })
}

fn parse_q_class(data: [u8; 2]) -> QClass {
  let class = (data[0] as u16) << 8 | data[1] as u16;
  match class {
    255 => QClass::Any,
    _ => QClass::Class(parse_class(data)),
  }
}

fn parse_q_response_type(data: u8) -> QuestionResponseType {
  if (0b10000000 & data) == 0b10000000 {
    return QuestionResponseType::QU;
  }
  QuestionResponseType::QM
}

fn parse_q_type(data: [u8; 2]) -> (QuestionResponseType, QType) {
  let q_type = ((0b01111111 & data[0]) as u16) << 8 | data[1] as u16;
  let response_type = parse_q_response_type(data[0]);
  (
    response_type,
    match q_type {
      252 => QType::AXFR,
      253 => QType::MAILB,
      254 => QType::MAILA,
      255 => QType::Any,
      _ => QType::Type(parse_type(data)),
    },
  )
}

pub fn parse_queries_v2<'a>(
  offset: usize,
  header: &Header,
  data: &'a [u8],
) -> Result<Vec<QueryV2<'a>>, ParseError> {
  let mut queries = vec![];
  let mut previous_index = 0;
  let mut current_offset = offset;
  for _ in 0..header.qd_count {
    let query = parse_query_v2(current_offset, &data[previous_index..])?;
    previous_index += query.size();
    current_offset += query.size();
    queries.push(query);
  }
  Ok(queries)
}

pub fn parse_queries(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<Query>, ParseError> {
  let mut queries = vec![];
  let mut previous_index = 0;
  let mut current_offset = start_offset;
  for _ in 0..header.qd_count {
    let query = parse_query(current_offset, &data[previous_index..])?;
    previous_index += query.size();
    current_offset += query.size() as u16;
    queries.push(query);
  }
  Ok(queries)
}

mod test {

  #[test]
  fn parse_q_type() {
    let test_data = [
      ([0, 254], super::QType::MAILA),
      ([0, 253], super::QType::MAILB),
      ([0, 252], super::QType::AXFR),
      ([0, 255], super::QType::Any),
      ([0, 1], super::QType::Type(super::Type::A)),
      ([0, 0], super::QType::Type(super::Type::Invalid)),
    ];

    for td in &test_data {
      let result = super::parse_q_type(td.0);
      assert_eq!((super::QuestionResponseType::QM, td.1), result);
    }
  }

  #[test]
  fn parse_q_class() {
    let test_data = [
      ([0, 255], super::QClass::Any),
      ([0, 1], super::QClass::Class(super::Class::IN)),
      ([0, 5], super::QClass::Class(super::Class::Invalid)),
    ];

    for td in &test_data {
      let result = super::parse_q_class(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn query_size_when_empty() {
    let query = super::Query {
      values: vec![super::Label::Value(0, None)],
      q_response_type: super::QuestionResponseType::QM,
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(5, query.size());
  }

  #[test]
  fn query_size_with_two_values() {
    let query = super::Query {
      values: vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, None),
      ],
      q_response_type: super::QuestionResponseType::QM,
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(12, query.size());
  }

  #[test]
  fn parse_query_with_to_short_data() {
    let data = [0, 1, 0, 0];
    let result = super::parse_query(0, &data);
    match result {
      Err(super::ParseError::QueryError(_)) => {}
      _ => assert!(false),
    }
  }

  #[test]
  fn parse_query_without_values() {
    let data = [0, 0, 1, 0, 1];
    let result = super::parse_query(0, &data);
    assert_eq!(
      Ok(super::Query {
        values: vec![super::Label::Value(0, None)],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN)
      }),
      result
    );
  }

  #[test]
  fn parse_query_with_three_values() {
    let data = [
      3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let result = super::parse_query(0, &data);
    assert_eq!(
      Ok(super::Query {
        values: vec![
          super::Label::Value(0, Some("abc".to_owned())),
          super::Label::Value(4, Some("de".to_owned())),
          super::Label::Value(7, Some("fghi".to_owned())),
          super::Label::Value(12, None)
        ],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN)
      }),
      result
    );
  }

  #[test]
  fn parse_queries() {
    let header_data = [0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];

    let data_piece_one = [
      3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let data_piece_two = [
      2, 97, 98, 3, 99, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let data = [data_piece_one, data_piece_two].concat();

    let header = crate::header::parse_header(&header_data).unwrap();
    let result = super::parse_queries(12, &header, &data);
    let expected = Ok(vec![
      super::Query {
        values: vec![
          super::Label::Value(12, Some("abc".to_owned())),
          super::Label::Value(16, Some("de".to_owned())),
          super::Label::Value(19, Some("fghi".to_owned())),
          super::Label::Value(24, None),
        ],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
      super::Query {
        values: vec![
          super::Label::Value(29, Some("ab".to_owned())),
          super::Label::Value(32, Some("cde".to_owned())),
          super::Label::Value(36, Some("fghi".to_owned())),
          super::Label::Value(41, None),
        ],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
    ]);

    assert_eq!(expected, result);
  }

  #[test]
  fn parse_query_with_value_values() {
    let data = [3, 97, 98, 99, 2, 100, 101, 1, 102, 0];
    let result = super::parse_name(0, &data);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, Some("f".to_owned())),
        super::Label::Value(9, None),
      ]),
      result
    );
  }

  #[test]
  fn parse_query_with_value_and_pointer_values() {
    let data = [3, 97, 98, 99, 2, 100, 101, 1, 102, 192, 10];
    let result = super::parse_name(0, &data);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, Some("f".to_owned())),
        super::Label::Pointer(9, 10),
      ]),
      result
    );
  }

  #[test]
  fn parse_q_response_type_for_unicast() {
    let data = 0b10000000;
    let result = super::parse_q_response_type(data);
    assert_eq!(super::QuestionResponseType::QU, result);
  }

  #[test]
  fn parse_q_response_type_for_multicast() {
    let data = 0b00000000;
    let result = super::parse_q_response_type(data);
    assert_eq!(super::QuestionResponseType::QM, result);
  }
}
