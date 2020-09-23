#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
  HeaderError(String),
  QueryLabelError(String),
  QueryError(String),
  ResourceRecordError(String),
}

const LABEL_TYPE_MASK: u8 = 0b11000000;
const LABEL_MASK_TYPE_VALUE: u8 = 0b00000000;
const LABEL_MASK_TYPE_POINTER: u8 = 0b11000000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelV2<'a> {
  Value(u16, Option<&'a [u8]>),
  Pointer(u16, u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Label {
  Value(u16, Option<String>),
  Pointer(u16, u16),
}

impl<'a> LabelV2<'a> {
  pub fn size(&self) -> usize {
    match self {
      LabelV2::Value(_, Some(l)) => l.len() + 1,
      LabelV2::Value(_, None) => 1,
      LabelV2::Pointer(_, _) => 2,
    }
  }
}

impl Label {
  pub fn size(&self) -> usize {
    match self {
      Label::Value(_, Some(l)) => l.len() + 1,
      Label::Value(_, None) => 1,
      Label::Pointer(_, _) => 2,
    }
  }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Class {
  Invalid,
  IN,
  CS,
  CH,
  HS,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Type {
  Invalid,
  A,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  NULL,
  WKS,
  PTR,
  HINFO,
  MINFO,
  MX,
  TXT,
}

pub fn parse_class(data: [u8; 2]) -> Class {
  let class = (data[0] as u16) << 8 | data[1] as u16;
  match class {
    1 => Class::IN,
    2 => Class::CS,
    3 => Class::CH,
    4 => Class::HS,
    _ => Class::Invalid,
  }
}

pub fn parse_type(data: [u8; 2]) -> Type {
  let t = (data[0] as u16) << 8 | data[1] as u16;
  match t {
    1 => Type::A,
    2 => Type::NS,
    3 => Type::MD,
    4 => Type::MF,
    5 => Type::CNAME,
    6 => Type::SOA,
    7 => Type::MB,
    8 => Type::MG,
    9 => Type::MR,
    10 => Type::NULL,
    11 => Type::WKS,
    12 => Type::PTR,
    13 => Type::HINFO,
    14 => Type::MINFO,
    15 => Type::MX,
    16 => Type::TXT,
    _ => Type::Invalid,
  }
}

fn read_until_termination_label_from_offset(labels: Vec<Label>, pointer_offset: u16) -> Vec<Label> {
  let mut end_found = false;
  labels
    .into_iter()
    .skip_while(|l| match l {
      Label::Value(offset, _) => *offset != pointer_offset,
      _ => true,
    })
    .take_while(|l| {
      if end_found {
        return false;
      }

      match l {
        Label::Value(_, None) => {
          end_found = true;
          true
        }
        _ => true,
      }
    })
    .collect()
}

fn resolve_name(all_labels: Vec<Label>, to_resolve: Vec<Label>) -> Vec<Label> {
  to_resolve
    .iter()
    .fold(vec![], |mut labels, label| match label {
      Label::Pointer(_, pointer) => {
        read_until_termination_label_from_offset(all_labels.clone(), *pointer)
          .into_iter()
          .for_each(|l| labels.push(l));
        labels
      }
      label => {
        labels.push(label.clone());
        labels
      }
    })
}

fn parse_label_value_v2(offset: usize, data: &[u8]) -> Result<LabelV2, ParseError> {
  let data = &data[offset..];

  let data_len = data.len();
  if data_len == 0 {
    return Err(ParseError::QueryLabelError(
      "Data is zero length".to_owned(),
    ));
  }
  let count = data[0];
  if count == 0 {
    return Ok(LabelV2::Value(offset as u16, None));
  }

  if count > 63 {
    return Err(ParseError::QueryLabelError(
      "Count exceeds limit of 63".to_owned(),
    ));
  }

  if (count as usize) > (data_len - 1) {
    return Err(ParseError::QueryLabelError(
      "Wrong label count. Count would overflow data".to_owned(),
    ));
  }

  let label_data = &data[1..((count + 1) as usize)];
  for &i in label_data {
    if i == 0 {
      return Err(ParseError::QueryLabelError(
        "Zero encountered before end of label".to_owned(),
      ));
    }
  }

  Ok(LabelV2::Value(offset as u16, Some(label_data)))
}

fn parse_label_value(current_offset: u16, data: &[u8]) -> Result<Label, ParseError> {
  let data_len = data.len();
  if data_len == 0 {
    return Err(ParseError::QueryLabelError(
      "Data is zero length".to_owned(),
    ));
  }

  let count = data[0];
  if count == 0 {
    return Ok(Label::Value(current_offset, None));
  }

  if count > 63 {
    return Err(ParseError::QueryLabelError(
      "Count exceeds limit of 63".to_owned(),
    ));
  }

  if (count as usize) > (data_len - 1) {
    return Err(ParseError::QueryLabelError(
      "Wrong label count. Count would overflow data".to_owned(),
    ));
  }

  let label_data = &data[1..((count + 1) as usize)];
  for &i in label_data {
    if i == 0 {
      return Err(ParseError::QueryLabelError(
        "Zero encountered before end of label".to_owned(),
      ));
    }
  }

  std::str::from_utf8(label_data)
    .map(|s| Label::Value(current_offset, Some(s.to_owned())))
    .map_err(|e| ParseError::QueryLabelError(e.to_string()))
}

fn parse_label_pointer(current_offset: u16, data: &[u8]) -> Result<Label, ParseError> {
  if data.len() < 2 {
    return Err(ParseError::QueryLabelError(
      "Trying to parse pointer label, but data is not long enough".to_owned(),
    ));
  }
  let pointer_value = ((!LABEL_MASK_TYPE_POINTER & data[0]) as u16) << 8 | data[1] as u16;
  Ok(Label::Pointer(current_offset, pointer_value))
}

fn parse_label_pointer_v2(offset: u16, data: &[u8]) -> Result<LabelV2, ParseError> {
  if data.len() < 2 {
    return Err(ParseError::QueryLabelError(
      "Trying to parse pointer label, but data is not long enough".to_owned(),
    ));
  }
  let pointer_value = ((!LABEL_MASK_TYPE_POINTER & data[0]) as u16) << 8 | data[1] as u16;
  Ok(LabelV2::Pointer(offset, pointer_value))
}

pub fn parse_name_v2(offset: usize, data: &[u8]) -> Result<Vec<LabelV2>, ParseError> {
  let mut values = vec![];
  let mut index = 0;
  let mut current_offset = offset;

  if data.len() == 0 {
    return Err(ParseError::QueryLabelError(
      "Failed to parse query values, zero length data".to_owned(),
    ));
  }

  loop {
    if data.len() <= index {
      return Err(ParseError::QueryLabelError(
        "Index going out of bounds when parsing query values".to_owned(),
      ));
    }

    let data = &data[index..];
    let label_type = LABEL_TYPE_MASK & data[0];

    let label = match label_type {
      LABEL_MASK_TYPE_POINTER => parse_label_pointer_v2(current_offset as u16, data),
      LABEL_MASK_TYPE_VALUE => parse_label_value_v2(current_offset, data),
      n => Err(ParseError::QueryLabelError(format!(
        "Unknown label type: {}",
        n
      ))),
    }?;
    current_offset += label.size();
    values.push(label.clone());

    match label {
      LabelV2::Pointer(_, _) => return Ok(values),
      LabelV2::Value(_, None) => return Ok(values),
      _ => {
        index += label.size();
      }
    }
  }
}

pub fn parse_name(start_offset: u16, data: &[u8]) -> Result<Vec<Label>, ParseError> {
  let mut values = vec![];
  let mut index = 0;
  let mut current_offset = start_offset;

  if data.len() == 0 {
    return Err(ParseError::QueryLabelError(
      "Failed to parse query values, zero length data".to_owned(),
    ));
  }

  loop {
    if data.len() <= index {
      return Err(ParseError::QueryLabelError(
        "Index going out of bounds when parsing query values".to_owned(),
      ));
    }

    let data = &data[index..];
    let label_type = LABEL_TYPE_MASK & data[0];

    let label = match label_type {
      LABEL_MASK_TYPE_POINTER => parse_label_pointer(current_offset, data),
      LABEL_MASK_TYPE_VALUE => parse_label_value(current_offset, data),
      n => Err(ParseError::QueryLabelError(format!(
        "Unknown label type: {}",
        n
      ))),
    }?;
    current_offset += label.size() as u16;
    values.push(label.clone());

    match label {
      Label::Pointer(_, _) => return Ok(values),
      Label::Value(_, None) => return Ok(values),
      _ => {
        index += label.size();
      }
    }
  }
}

mod test {

  #[test]
  fn parse_type() {
    let test_data = [
      ([0, 0], super::Type::Invalid),
      ([0, 1], super::Type::A),
      ([0, 2], super::Type::NS),
      ([0, 3], super::Type::MD),
      ([0, 4], super::Type::MF),
      ([0, 5], super::Type::CNAME),
      ([0, 6], super::Type::SOA),
      ([0, 7], super::Type::MB),
      ([0, 8], super::Type::MG),
      ([0, 9], super::Type::MR),
      ([0, 10], super::Type::NULL),
      ([0, 11], super::Type::WKS),
      ([0, 12], super::Type::PTR),
      ([0, 13], super::Type::HINFO),
      ([0, 14], super::Type::MINFO),
      ([0, 15], super::Type::MX),
      ([0, 16], super::Type::TXT),
      ([0, 17], super::Type::Invalid),
    ];

    for td in &test_data {
      let result = super::parse_type(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn parse_name_label_with_zero_length() {
    if let Ok(_) = super::parse_name(0, &[]) {
      assert!(false);
    }
  }

  #[test]
  fn parse_name_with_count_zero() {
    let result = super::parse_name(0, &[0]);
    assert_eq!(Ok(vec![super::Label::Value(0, None)]), result);
  }

  #[test]
  fn parse_name_with_overflowing_label_count() {
    match super::parse_name(0, &[1]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_label_higher_than_63_count() {
    match super::parse_name(0, &[64]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_premature_zero_in_label() {
    match super::parse_name(0, &[4, 97, 98, 0, 99]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_label_text_abc() {
    let result = super::parse_name(0, &[3, 97, 98, 99, 0]);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, None)
      ]),
      result
    );
  }

  #[test]
  fn parse_class() {
    let test_data = [
      ([0, 0], super::Class::Invalid),
      ([0, 1], super::Class::IN),
      ([0, 2], super::Class::CS),
      ([0, 3], super::Class::CH),
      ([0, 4], super::Class::HS),
      ([0, 5], super::Class::Invalid),
    ];

    for td in &test_data {
      let result = super::parse_class(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn parse_label_pointer() {
    let data = [193, 10];
    let result = super::parse_label_pointer(0, &data);
    assert_eq!(Ok(super::Label::Pointer(0, 266)), result);
  }

  #[test]
  fn parse_label_pointer_and_fail() {
    let data = [193];
    let result = super::parse_label_pointer(0, &data);
    match result {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_label_value() {
    let data = [8, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(
      Ok(super::Label::Value(0, Some("abcdefgh".to_owned()))),
      result
    );
  }

  #[test]
  fn parse_label_value_empty() {
    let data = [0, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(Ok(super::Label::Value(0, None)), result);
  }

  #[test]
  fn label_size_value() {
    let data = [8, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(Ok(9), result.map(|r| r.size()));
  }

  #[test]
  fn label_size_pointer() {
    let data = [192, 10];
    let result = super::parse_label_pointer(0, &data);
    assert_eq!(Ok(2), result.map(|r| r.size()));
  }

  #[test]
  fn read_until_termination_label_from_offset() {
    let labels = vec![
      super::Label::Value(0, Some("abc".to_owned())),
      super::Label::Value(4, Some("def".to_owned())),
      super::Label::Value(8, None),
      super::Label::Value(12, Some("ghi".to_owned())),
      super::Label::Value(16, None),
      super::Label::Value(20, Some("jkl".to_owned())),
      super::Label::Value(24, None),
    ];

    let result = super::read_until_termination_label_from_offset(labels, 12);
    assert_eq!(
      vec![
        super::Label::Value(12, Some("ghi".to_owned())),
        super::Label::Value(16, None)
      ],
      result
    );
  }

  #[test]
  fn resolve_name() {
    let labels = vec![
      super::Label::Value(0, Some("abc".to_owned())),
      super::Label::Value(4, Some("def".to_owned())),
      super::Label::Value(8, None),
      super::Label::Value(12, Some("ghi".to_owned())),
      super::Label::Value(16, None),
      super::Label::Value(20, Some("jkl".to_owned())),
      super::Label::Pointer(24, 0),
    ];

    let result = super::resolve_name(labels.clone(), labels[5..].to_vec());
    assert_eq!(
      vec![
        super::Label::Value(20, Some("jkl".to_owned())),
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("def".to_owned())),
        super::Label::Value(8, None),
      ],
      result
    );
  }
}
