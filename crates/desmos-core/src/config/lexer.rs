//! Tokenizer for the Desmos TOML subset.

use super::ParseError;
use super::ParseErrorKind;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    LBracket,
    RBracket,
    Eq,
    Comma,
    Dot,
    String(String),
    Integer(i64),
    Float(f64),
    Bool(bool),
    Ident(String),
    Newline,
    Eof,
}

impl Token {
    pub fn describe(&self) -> String {
        match self {
            Self::LBracket => "`[`".into(),
            Self::RBracket => "`]`".into(),
            Self::Eq => "`=`".into(),
            Self::Comma => "`,`".into(),
            Self::Dot => "`.`".into(),
            Self::String(_) => "string".into(),
            Self::Integer(_) => "integer".into(),
            Self::Float(_) => "float".into(),
            Self::Bool(_) => "boolean".into(),
            Self::Ident(_) => "identifier".into(),
            Self::Newline => "newline".into(),
            Self::Eof => "end of input".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spanned {
    pub tok: Token,
    pub line: usize,
    pub col: usize,
}

pub fn tokenize(input: &str) -> Result<Vec<Spanned>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut out: Vec<Spanned> = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    while i < chars.len() {
        let c = chars[i];
        let start_line = line;
        let start_col = col;

        match c {
            ' ' | '\t' => {
                i += 1;
                col += 1;
            }
            '\r' => {
                i += 1;
            }
            '\n' => {
                out.push(Spanned { tok: Token::Newline, line: start_line, col: start_col });
                i += 1;
                line += 1;
                col = 1;
            }
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '[' => {
                out.push(Spanned { tok: Token::LBracket, line: start_line, col: start_col });
                i += 1;
                col += 1;
            }
            ']' => {
                out.push(Spanned { tok: Token::RBracket, line: start_line, col: start_col });
                i += 1;
                col += 1;
            }
            '=' => {
                out.push(Spanned { tok: Token::Eq, line: start_line, col: start_col });
                i += 1;
                col += 1;
            }
            ',' => {
                out.push(Spanned { tok: Token::Comma, line: start_line, col: start_col });
                i += 1;
                col += 1;
            }
            '.' => {
                out.push(Spanned { tok: Token::Dot, line: start_line, col: start_col });
                i += 1;
                col += 1;
            }
            '"' => {
                let (s, consumed) = read_string(&chars, i, start_line, start_col)?;
                out.push(Spanned { tok: Token::String(s), line: start_line, col: start_col });
                i += consumed;
                col += consumed;
            }
            c if is_number_start(c, &chars, i) => {
                let (tok, consumed) = read_number(&chars, i, start_line, start_col)?;
                out.push(Spanned { tok, line: start_line, col: start_col });
                col += consumed;
                i += consumed;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let (tok, consumed) = read_ident(&chars, i);
                out.push(Spanned { tok, line: start_line, col: start_col });
                col += consumed;
                i += consumed;
            }
            other => {
                return Err(ParseError::new(
                    ParseErrorKind::UnexpectedChar(other),
                    start_line,
                    start_col,
                ));
            }
        }
    }

    out.push(Spanned { tok: Token::Eof, line, col });
    Ok(out)
}

fn is_number_start(c: char, chars: &[char], i: usize) -> bool {
    if c.is_ascii_digit() {
        return true;
    }
    if (c == '-' || c == '+') && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
        return true;
    }
    false
}

fn read_string(
    chars: &[char],
    start: usize,
    line: usize,
    col: usize,
) -> Result<(String, usize), ParseError> {
    let mut i = start + 1;
    let mut s = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            return Err(ParseError::new(ParseErrorKind::UnterminatedString, line, col));
        }
        if c == '"' {
            return Ok((s, i - start + 1));
        }
        if c == '\\' {
            i += 1;
            if i >= chars.len() {
                return Err(ParseError::new(ParseErrorKind::UnterminatedString, line, col));
            }
            let esc = chars[i];
            let decoded = match esc {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '"' => '"',
                '\\' => '\\',
                other => {
                    return Err(ParseError::new(ParseErrorKind::InvalidEscape(other), line, col));
                }
            };
            s.push(decoded);
            i += 1;
            continue;
        }
        s.push(c);
        i += 1;
    }
    Err(ParseError::new(ParseErrorKind::UnterminatedString, line, col))
}

fn read_number(
    chars: &[char],
    start: usize,
    line: usize,
    col: usize,
) -> Result<(Token, usize), ParseError> {
    let mut end = start;
    if chars[end] == '-' || chars[end] == '+' {
        end += 1;
    }
    while end < chars.len() && chars[end].is_ascii_digit() {
        end += 1;
    }
    let mut is_float = false;
    if end < chars.len()
        && chars[end] == '.'
        && end + 1 < chars.len()
        && chars[end + 1].is_ascii_digit()
    {
        is_float = true;
        end += 1;
        while end < chars.len() && chars[end].is_ascii_digit() {
            end += 1;
        }
    }
    let lexeme: String = chars[start..end].iter().collect();
    let tok = if is_float {
        let f: f64 = lexeme.parse().map_err(|_| {
            ParseError::new(ParseErrorKind::InvalidNumber(lexeme.clone()), line, col)
        })?;
        Token::Float(f)
    } else {
        let n: i64 = lexeme.parse().map_err(|_| {
            ParseError::new(ParseErrorKind::InvalidNumber(lexeme.clone()), line, col)
        })?;
        Token::Integer(n)
    };
    Ok((tok, end - start))
}

fn read_ident(chars: &[char], start: usize) -> (Token, usize) {
    let mut end = start;
    while end < chars.len()
        && (chars[end].is_ascii_alphanumeric() || chars[end] == '_' || chars[end] == '-')
    {
        end += 1;
    }
    let word: String = chars[start..end].iter().collect();
    let tok = match word.as_str() {
        "true" => Token::Bool(true),
        "false" => Token::Bool(false),
        _ => Token::Ident(word),
    };
    (tok, end - start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Token> {
        tokenize(src).unwrap().into_iter().map(|s| s.tok).collect()
    }

    #[test]
    fn tokenizes_empty_input() {
        assert_eq!(toks(""), vec![Token::Eof]);
    }

    #[test]
    fn tokenizes_section_header() {
        assert_eq!(
            toks("[server.auth]"),
            vec![
                Token::LBracket,
                Token::Ident("server".into()),
                Token::Dot,
                Token::Ident("auth".into()),
                Token::RBracket,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tokenizes_key_value() {
        assert_eq!(
            toks("mode = \"client\""),
            vec![
                Token::Ident("mode".into()),
                Token::Eq,
                Token::String("client".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tokenizes_numbers_and_bools() {
        assert_eq!(
            toks("a = 42\nb = -2.5\nc = true\nd = false"),
            vec![
                Token::Ident("a".into()),
                Token::Eq,
                Token::Integer(42),
                Token::Newline,
                Token::Ident("b".into()),
                Token::Eq,
                Token::Float(-2.5),
                Token::Newline,
                Token::Ident("c".into()),
                Token::Eq,
                Token::Bool(true),
                Token::Newline,
                Token::Ident("d".into()),
                Token::Eq,
                Token::Bool(false),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn skips_comments() {
        assert_eq!(
            toks("# this is a comment\nk = 1 # trailing\n"),
            vec![
                Token::Newline,
                Token::Ident("k".into()),
                Token::Eq,
                Token::Integer(1),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn reports_line_and_col_for_unexpected_char() {
        let e = tokenize("a = 1\n?").unwrap_err();
        assert_eq!(e.line, 2);
        assert_eq!(e.col, 1);
        assert!(matches!(e.kind, ParseErrorKind::UnexpectedChar('?')));
    }
}
