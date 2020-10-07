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
pub enum Label {
  Value(u16, Option<Vec<u8>>),
  Pointer(u16, u16),
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

fn resolve_pointer(all_labels: &Vec<Label>, pointer_value: u16) -> Vec<Label> {
  let mut take_inclusive_found = false;
  all_labels
    .iter()
    .skip_while(|l| match l {
      Label::Value(index, _) => *index != pointer_value,
      _ => false,
    })
    .take_while(|l| {
      if take_inclusive_found {
        return false;
      }

      match l {
        Label::Value(_, None) => {
          take_inclusive_found = true;
          true
        }
        _ => true,
      }
    })
    .fold(vec![], |mut resolved_data, label| {
      resolved_data.push(label.clone());
      resolved_data
    })
}

pub fn extract_domain_name(label_store: &Vec<Label>, name_labels: &[Label]) -> String {
  let mut found_pointer = false;
  name_labels
    .iter()
    .take_while(|l| {
      if found_pointer {
        return false;
      }

      match l {
        Label::Value(_, None) => false,
        Label::Pointer(_, _) => {
          found_pointer = true;
          true
        }
        _ => true,
      }
    })
    .map(|l| match l {
      Label::Pointer(_, pointer) => {
        let pointer_name_labels = resolve_pointer(label_store, *pointer);
        extract_domain_name(label_store, &pointer_name_labels)
      }
      Label::Value(_, Some(data)) => std::str::from_utf8(data).unwrap().to_owned(),
      Label::Value(_, None) => "".to_owned(),
    })
    .collect::<Vec<String>>()
    .join(".")
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
  match u16::from_be_bytes(data) {
    1 => Class::IN,
    2 => Class::CS,
    3 => Class::CH,
    4 => Class::HS,
    _ => Class::Invalid,
  }
}

pub fn parse_type(data: [u8; 2]) -> Type {
  match u16::from_be_bytes(data) {
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
fn parse_label_value(offset: usize, data: &[u8]) -> Result<Label, ParseError> {
  let data = &data[offset..];

  let data_len = data.len();
  if data_len == 0 {
    return Err(ParseError::QueryLabelError(
      "Data is zero length".to_owned(),
    ));
  }
  let count = data[0];
  if count == 0 {
    return Ok(Label::Value(offset as u16, None));
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

  Ok(Label::Value(offset as u16, Some(Vec::from(label_data))))
}

pub fn parse_name(offset: usize, data: &[u8]) -> Result<Vec<Label>, ParseError> {
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

    let label_type = LABEL_TYPE_MASK & data[current_offset];

    let label = match label_type {
      LABEL_MASK_TYPE_POINTER => parse_label_pointer(current_offset, data),
      LABEL_MASK_TYPE_VALUE => parse_label_value(current_offset, data),
      n => Err(ParseError::QueryLabelError(format!(
        "Unknown label type: {}",
        n
      ))),
    }?;
    current_offset += label.size();
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

fn parse_label_pointer(offset: usize, data: &[u8]) -> Result<Label, ParseError> {
  if data.len() < 2 {
    return Err(ParseError::QueryLabelError(
      "Trying to parse pointer label, but data is not long enough".to_owned(),
    ));
  }
  let pointer_value =
    ((!LABEL_MASK_TYPE_POINTER & data[offset]) as u16) << 8 | data[offset + 1] as u16;
  Ok(Label::Pointer(offset as u16, pointer_value))
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
        super::Label::Value(0, Some(vec![97, 98, 99])),
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
      Ok(super::Label::Value(
        0,
        Some(vec![97, 98, 99, 100, 101, 102, 103, 104])
      )),
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
  fn parse_name() {
    let data = &[3, 97, 98, 99, 2, 97, 98, 0, 4, 97, 98, 99, 100, 1, 97, 0];
    let result = super::parse_name(0, data);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some(vec![97, 98, 99])),
        super::Label::Value(4, Some(vec![97, 98])),
        super::Label::Value(7, None)
      ]),
      result
    );
  }

  #[test]
  fn resolve_pointer() {
    let labels = vec![
      super::Label::Value(0, Some(vec![1, 2, 3])),
      super::Label::Value(4, None),
      super::Label::Value(5, Some(vec![4, 5, 6])),
      super::Label::Value(9, Some(vec![7, 8])),
      super::Label::Value(12, None),
      super::Label::Value(13, Some(vec![9])),
      super::Label::Value(15, Some(vec![10])),
      super::Label::Value(17, None),
    ];

    let result = super::resolve_pointer(&labels, 5);
    assert_eq!(
      vec![
        super::Label::Value(5, Some(vec![4, 5, 6])),
        super::Label::Value(9, Some(vec![7, 8])),
        super::Label::Value(12, None)
      ],
      result
    );
  }

  #[test]
  fn extract_domain_name() {
    let all_labels = vec![
      super::Label::Value(0, Some(vec![120, 121])),
      super::Label::Value(3, None),
      super::Label::Value(4, Some(vec![97, 98, 99])),
      super::Label::Value(8, Some(vec![100, 101, 102])),
      super::Label::Value(12, Some(vec![103, 104, 105])),
      super::Label::Value(16, None),
      super::Label::Value(17, Some(vec![97, 98])),
      super::Label::Value(20, Some(vec![99, 100, 101])),
      super::Label::Value(24, Some(vec![102, 103, 104])),
      super::Label::Pointer(28, 4),
    ];

    let domain_name = super::extract_domain_name(&all_labels, &all_labels[6..]);
    assert_eq!("ab.cde.fgh.abc.def.ghi".to_owned(), domain_name);
  }
}
