#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
  HeaderError(String),
  QueryLabelError(String),
  QueryError(String),
  ResourceRecordError(String),
}
