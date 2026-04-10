//! Recursive-descent parser that consumes a [`Spanned`] token stream and
//! produces a [`Value`] tree. See [`super::parse`] for the entry point.

use std::collections::BTreeMap;

use super::lexer::Spanned;
use super::lexer::Token;
use super::ParseError;
use super::ParseErrorKind;
use super::Value;

pub struct Parser {
    tokens: Vec<Spanned>,
    pos: usize,
}

#[derive(Debug, Clone)]
enum PathSeg {
    Table(String),
    ArrayTail(String),
}

impl Parser {
    pub fn new(tokens: Vec<Spanned>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse_document(&mut self) -> Result<Value, ParseError> {
        let mut root: BTreeMap<String, Value> = BTreeMap::new();
        let mut current: Vec<PathSeg> = Vec::new();

        loop {
            self.skip_newlines();
            if self.at_eof() {
                break;
            }

            if matches!(self.peek_tok(), Token::LBracket) {
                self.advance();
                let is_array_of_tables = matches!(self.peek_tok(), Token::LBracket);
                if is_array_of_tables {
                    self.advance();
                }
                let path = self.parse_dotted_key()?;
                self.expect_token(&Token::RBracket, "]")?;
                if is_array_of_tables {
                    self.expect_token(&Token::RBracket, "]")?;
                }
                self.expect_newline_or_eof()?;
                current = if is_array_of_tables {
                    init_array_of_tables(
                        &mut root,
                        &path,
                        &self.tokens[self.pos.min(self.tokens.len() - 1)],
                    )?
                } else {
                    init_table(&mut root, &path)?
                };
                continue;
            }

            if matches!(self.peek_tok(), Token::Ident(_)) {
                let sp = self.peek().clone();
                let key =
                    if let Token::Ident(name) = &sp.tok { name.clone() } else { unreachable!() };
                self.advance();
                self.expect_token(&Token::Eq, "=")?;
                let value = self.parse_value()?;
                self.expect_newline_or_eof()?;
                insert_value(&mut root, &current, key, value, sp.line, sp.col)?;
                continue;
            }

            let sp = self.peek().clone();
            return Err(ParseError::new(
                ParseErrorKind::UnexpectedToken {
                    expected: "section header or key",
                    got: sp.tok.describe(),
                },
                sp.line,
                sp.col,
            ));
        }

        Ok(Value::Table(root))
    }

    fn parse_dotted_key(&mut self) -> Result<Vec<String>, ParseError> {
        let mut parts = Vec::new();
        parts.push(self.parse_ident()?);
        while matches!(self.peek_tok(), Token::Dot) {
            self.advance();
            parts.push(self.parse_ident()?);
        }
        Ok(parts)
    }

    fn parse_ident(&mut self) -> Result<String, ParseError> {
        let sp = self.peek().clone();
        if let Token::Ident(name) = &sp.tok {
            let out = name.clone();
            self.advance();
            Ok(out)
        } else {
            Err(ParseError::new(
                ParseErrorKind::UnexpectedToken { expected: "identifier", got: sp.tok.describe() },
                sp.line,
                sp.col,
            ))
        }
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        let sp = self.peek().clone();
        match &sp.tok {
            Token::String(s) => {
                let v = Value::String(s.clone());
                self.advance();
                Ok(v)
            }
            Token::Integer(i) => {
                let v = Value::Integer(*i);
                self.advance();
                Ok(v)
            }
            Token::Float(f) => {
                let v = Value::Float(*f);
                self.advance();
                Ok(v)
            }
            Token::Bool(b) => {
                let v = Value::Boolean(*b);
                self.advance();
                Ok(v)
            }
            Token::LBracket => {
                self.advance();
                let mut items = Vec::new();
                loop {
                    self.skip_newlines();
                    if matches!(self.peek_tok(), Token::RBracket) {
                        self.advance();
                        break;
                    }
                    items.push(self.parse_value()?);
                    self.skip_newlines();
                    if matches!(self.peek_tok(), Token::Comma) {
                        self.advance();
                        continue;
                    }
                    self.skip_newlines();
                    self.expect_token(&Token::RBracket, "]")?;
                    break;
                }
                Ok(Value::Array(items))
            }
            _ => Err(ParseError::new(
                ParseErrorKind::UnexpectedToken { expected: "value", got: sp.tok.describe() },
                sp.line,
                sp.col,
            )),
        }
    }

    fn peek(&self) -> &Spanned {
        &self.tokens[self.pos]
    }

    fn peek_tok(&self) -> &Token {
        &self.tokens[self.pos].tok
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek_tok(), Token::Eof)
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek_tok(), Token::Newline) {
            self.advance();
        }
    }

    fn expect_token(&mut self, want: &Token, expected: &'static str) -> Result<(), ParseError> {
        if std::mem::discriminant(self.peek_tok()) == std::mem::discriminant(want) {
            self.advance();
            Ok(())
        } else {
            let sp = self.peek().clone();
            Err(ParseError::new(
                ParseErrorKind::UnexpectedToken { expected, got: sp.tok.describe() },
                sp.line,
                sp.col,
            ))
        }
    }

    fn expect_newline_or_eof(&mut self) -> Result<(), ParseError> {
        match self.peek_tok() {
            Token::Newline => {
                self.advance();
                Ok(())
            }
            Token::Eof => Ok(()),
            _ => {
                let sp = self.peek().clone();
                Err(ParseError::new(
                    ParseErrorKind::UnexpectedToken { expected: "newline", got: sp.tok.describe() },
                    sp.line,
                    sp.col,
                ))
            }
        }
    }
}

fn init_table(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
) -> Result<Vec<PathSeg>, ParseError> {
    let segs: Vec<PathSeg> = path.iter().map(|s| PathSeg::Table(s.clone())).collect();
    let _ = navigate_mut(root, &segs)?;
    Ok(segs)
}

fn init_array_of_tables(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
    header_span: &Spanned,
) -> Result<Vec<PathSeg>, ParseError> {
    let (last, init) = path.split_last().ok_or_else(|| {
        ParseError::new(
            ParseErrorKind::UnexpectedToken { expected: "identifier", got: "empty".into() },
            header_span.line,
            header_span.col,
        )
    })?;
    let init_segs: Vec<PathSeg> = init.iter().map(|s| PathSeg::Table(s.clone())).collect();
    let container = navigate_mut(root, &init_segs)?;
    let entry = container.entry(last.clone()).or_insert_with(|| Value::Array(Vec::new()));
    match entry {
        Value::Array(arr) => {
            arr.push(Value::Table(BTreeMap::new()));
        }
        other => {
            return Err(ParseError::new(
                ParseErrorKind::DuplicateKey(format!(
                    "{last}: expected array of tables, got {}",
                    other.type_name()
                )),
                header_span.line,
                header_span.col,
            ));
        }
    }
    let mut segs = init_segs;
    segs.push(PathSeg::ArrayTail(last.clone()));
    Ok(segs)
}

fn navigate_mut<'a>(
    root: &'a mut BTreeMap<String, Value>,
    path: &[PathSeg],
) -> Result<&'a mut BTreeMap<String, Value>, ParseError> {
    let mut current: &'a mut BTreeMap<String, Value> = root;
    for seg in path {
        match seg {
            PathSeg::Table(k) => {
                let entry =
                    current.entry(k.clone()).or_insert_with(|| Value::Table(BTreeMap::new()));
                match entry {
                    Value::Table(t) => {
                        current = t;
                    }
                    other => {
                        return Err(ParseError::new(
                            ParseErrorKind::DuplicateKey(format!(
                                "{k}: expected table, got {}",
                                other.type_name()
                            )),
                            0,
                            0,
                        ));
                    }
                }
            }
            PathSeg::ArrayTail(k) => {
                let entry = current
                    .entry(k.clone())
                    .or_insert_with(|| Value::Array(vec![Value::Table(BTreeMap::new())]));
                match entry {
                    Value::Array(arr) => {
                        if arr.is_empty() {
                            arr.push(Value::Table(BTreeMap::new()));
                        }
                        let last = arr.last_mut().expect("array has at least one element");
                        match last {
                            Value::Table(t) => {
                                current = t;
                            }
                            _ => {
                                return Err(ParseError::new(
                                    ParseErrorKind::DuplicateKey(format!(
                                        "{k}: array must contain tables only"
                                    )),
                                    0,
                                    0,
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(ParseError::new(
                            ParseErrorKind::DuplicateKey(format!("{k}: expected array of tables")),
                            0,
                            0,
                        ));
                    }
                }
            }
        }
    }
    Ok(current)
}

fn insert_value(
    root: &mut BTreeMap<String, Value>,
    current: &[PathSeg],
    key: String,
    value: Value,
    line: usize,
    col: usize,
) -> Result<(), ParseError> {
    let table = navigate_mut(root, current)?;
    if table.contains_key(&key) {
        return Err(ParseError::new(ParseErrorKind::DuplicateKey(key), line, col));
    }
    table.insert(key, value);
    Ok(())
}
