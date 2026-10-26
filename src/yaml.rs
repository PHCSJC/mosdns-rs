//! Tiny YAML subset parser: enough for mosdns config files.
//! Supports: nested maps, block sequences, scalars (plain/quoted), comments.

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Str(s) => s.parse::<i64>().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_string_list(&self) -> Vec<String> {
        match self {
            Value::Null => vec![],
            Value::Str(s) => vec![s.clone()],
            Value::List(l) => l
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => vec![],
        }
    }
}

struct Line {
    indent: usize,
    content: String,
    no: usize,
}

fn strip_comment(s: &str) -> String {
    let mut out = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_space = true;
    for ch in s.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                out.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                out.push(ch);
            }
            '#' if !in_single && !in_double && prev_space => break,
            _ => {
                out.push(ch);
            }
        }
        prev_space = ch == ' ' || ch == '\t';
    }
    out
}

fn scalar(s: &str) -> Value {
    let t = s.trim();
    if t.is_empty() {
        return Value::Null;
    }
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
    {
        return Value::Str(t[1..t.len() - 1].to_string());
    }
    if t == "true" {
        return Value::Bool(true);
    }
    if t == "false" {
        return Value::Bool(false);
    }
    if t == "~" || t == "null" {
        return Value::Null;
    }
    if let Ok(i) = t.parse::<i64>() {
        return Value::Int(i);
    }
    Value::Str(t.to_string())
}

/// Split "key: value" -> (key, value). Returns None if the line is not a mapping entry.
fn split_key(s: &str) -> Option<(String, String)> {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                let rest = &s[i + 1..];
                if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
                    let key = s[..i].trim().trim_matches('"').trim_matches('\'').to_string();
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key, rest.trim().to_string()));
                }
            }
            _ => {}
        }
    }
    None
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut lines: Vec<Line> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let s = strip_comment(raw);
        let t = s.trim_end();
        if t.trim().is_empty() {
            continue;
        }
        let indent = t.len() - t.trim_start().len();
        lines.push(Line {
            indent,
            content: t.trim_start().to_string(),
            no: i + 1,
        });
    }
    if lines.is_empty() {
        return Ok(Value::Null);
    }
    let mut idx = 0usize;
    let v = parse_block(&lines, &mut idx, lines[0].indent)?;
    Ok(v)
}

fn is_list_item(s: &str) -> bool {
    s == "-" || s.starts_with("- ")
}

fn parse_block(lines: &[Line], idx: &mut usize, indent: usize) -> Result<Value, String> {
    if *idx >= lines.len() {
        return Ok(Value::Null);
    }
    if is_list_item(&lines[*idx].content) {
        parse_list(lines, idx, indent)
    } else {
        parse_map(lines, idx, indent)
    }
}

fn parse_list(lines: &[Line], idx: &mut usize, indent: usize) -> Result<Value, String> {
    let mut out = Vec::new();
    while *idx < lines.len() && lines[*idx].indent == indent && is_list_item(&lines[*idx].content) {
        let content = lines[*idx].content[1..].trim().to_string();
        *idx += 1;
        if content.is_empty() {
            // nested block belonging to this item
            if *idx < lines.len() && lines[*idx].indent > indent {
                let child_indent = lines[*idx].indent;
                out.push(parse_block(lines, idx, child_indent)?);
            } else {
                out.push(Value::Null);
            }
            continue;
        }
        if let Some((k, rest)) = split_key(&content) {
            // inline start of a mapping item; continuation keys are indented deeper
            let mut pairs: Vec<(String, Value)> = Vec::new();
            let val = if rest.is_empty() {
                if *idx < lines.len() && lines[*idx].indent > indent {
                    let child_indent = lines[*idx].indent;
                    parse_block(lines, idx, child_indent)?
                } else {
                    Value::Null
                }
            } else {
                scalar(&rest)
            };
            pairs.push((k, val));

            let cont_indent = if *idx < lines.len()
                && lines[*idx].indent > indent
                && !is_list_item(&lines[*idx].content)
            {
                Some(lines[*idx].indent)
            } else {
                None
            };
            if let Some(ci) = cont_indent {
                let more = parse_map(lines, idx, ci)?;
                if let Value::Map(m) = more {
                    pairs.extend(m);
                }
            }
            out.push(Value::Map(pairs));
        } else {
            out.push(scalar(&content));
        }
    }
    Ok(Value::List(out))
}

fn parse_map(lines: &[Line], idx: &mut usize, indent: usize) -> Result<Value, String> {
    let mut out: Vec<(String, Value)> = Vec::new();
    while *idx < lines.len() && lines[*idx].indent == indent && !is_list_item(&lines[*idx].content)
    {
        let line = &lines[*idx];
        let (k, rest) = match split_key(&line.content) {
            Some(kv) => kv,
            None => {
                return Err(format!(
                    "line {}: cannot parse as mapping entry: {}",
                    line.no, line.content
                ))
            }
        };
        *idx += 1;
        let val = if rest.is_empty() {
            if *idx < lines.len() && lines[*idx].indent > indent {
                let child_indent = lines[*idx].indent;
                parse_block(lines, idx, child_indent)?
            } else {
                Value::Null
            }
        } else {
            scalar(&rest)
        };
        out.push((k, val));
    }
    Ok(Value::Map(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let s = r#"
log:
  level: info
  file: "/var/log/mosdns.log"

plugins:
  - tag: cache
    type: cache
    args:
      size: 10240
      lazy_cache_ttl: 86400
  - tag: seq
    type: sequence
    args:
      - exec: $hosts
      - matches: qtype 12 65
        exec: reject 0
"#;
        let v = parse(s).unwrap();
        let plugins = v.get("plugins").unwrap().as_list().unwrap();
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].get("tag").unwrap().as_str().unwrap(), "cache");
        let seq = plugins[1].get("args").unwrap().as_list().unwrap();
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[1].get("matches").unwrap().as_str().unwrap(), "qtype 12 65");
    }
}
