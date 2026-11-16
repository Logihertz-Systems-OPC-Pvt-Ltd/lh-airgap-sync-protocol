//! Clean-room, zero-dependency recursive JSON lexer, parser, and canonical serializer.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            Self::Object(obj) => Some(obj.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.as_f64())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let chars: Vec<char> = input.chars().collect();
        let mut idx = 0;
        skip_whitespace(&chars, &mut idx);
        let val = parse_value(&chars, &mut idx)?;
        skip_whitespace(&chars, &mut idx);
        if idx != chars.len() {
            return Err(format!("Trailing unexpected character at position {}", idx));
        }
        Ok(val)
    }

    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        format_pretty(self, 0, &mut out);
        out
    }
}

fn skip_whitespace(chars: &[char], idx: &mut usize) {
    while *idx < chars.len() && chars[*idx].is_whitespace() {
        *idx += 1;
    }
}

fn parse_value(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    skip_whitespace(chars, idx);
    if *idx >= chars.len() {
        return Err("Unexpected end of JSON input".to_string());
    }

    match chars[*idx] {
        'n' => parse_null(chars, idx),
        't' | 'f' => parse_bool(chars, idx),
        '"' => parse_string(chars, idx).map(JsonValue::String),
        '[' => parse_array(chars, idx),
        '{' => parse_object(chars, idx),
        '-' | '0'..='9' => parse_number(chars, idx),
        c => Err(format!("Unexpected character '{}' at position {}", c, idx)),
    }
}

fn parse_null(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['n', 'u', 'l', 'l'] {
        *idx += 4;
        Ok(JsonValue::Null)
    } else {
        Err(format!("Invalid literal starting at position {}", idx))
    }
}

fn parse_bool(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['t', 'r', 'u', 'e'] {
        *idx += 4;
        Ok(JsonValue::Bool(true))
    } else if *idx + 5 <= chars.len() && chars[*idx..*idx + 5] == ['f', 'a', 'l', 's', 'e'] {
        *idx += 5;
        Ok(JsonValue::Bool(false))
    } else {
        Err(format!("Invalid boolean literal at position {}", idx))
    }
}

fn parse_string(chars: &[char], idx: &mut usize) -> Result<String, String> {
    *idx += 1; // skip opening quote
    let mut s = String::new();
    while *idx < chars.len() {
        let c = chars[*idx];
        *idx += 1;
        if c == '"' {
            return Ok(s);
        } else if c == '\\' {
            if *idx >= chars.len() {
                return Err("Unterminated escape sequence in string".to_string());
            }
            let esc = chars[*idx];
            *idx += 1;
            match esc {
                '"' => s.push('"'),
                '\\' => s.push('\\'),
                '/' => s.push('/'),
                'b' => s.push('\x08'),
                'f' => s.push('\x0c'),
                'n' => s.push('\n'),
                'r' => s.push('\r'),
                't' => s.push('\t'),
                'u' => {
                    if *idx + 4 > chars.len() {
                        return Err("Invalid unicode escape".to_string());
                    }
                    let hex_str: String = chars[*idx..*idx + 4].iter().collect();
                    *idx += 4;
                    let code = u32::from_str_radix(&hex_str, 16)
                        .map_err(|e| format!("Invalid unicode escape \\u{}: {}", hex_str, e))?;
                    if let Some(ch) = char::from_u32(code) {
                        s.push(ch);
                    } else {
                        s.push('?');
                    }
                }
                _ => s.push(esc),
            }
        } else {
            s.push(c);
        }
    }
    Err("Unterminated string literal".to_string())
}

fn parse_number(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    let start = *idx;
    if chars[*idx] == '-' {
        *idx += 1;
    }
    while *idx < chars.len() && chars[*idx].is_ascii_digit() {
        *idx += 1;
    }
    if *idx < chars.len() && chars[*idx] == '.' {
        *idx += 1;
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }
    if *idx < chars.len() && (chars[*idx] == 'e' || chars[*idx] == 'E') {
        *idx += 1;
        if *idx < chars.len() && (chars[*idx] == '+' || chars[*idx] == '-') {
            *idx += 1;
        }
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }
    let num_str: String = chars[start..*idx].iter().collect();
    let num: f64 = num_str
        .parse()
        .map_err(|e| format!("Invalid number '{}': {}", num_str, e))?;
    Ok(JsonValue::Number(num))
}

fn parse_array(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    *idx += 1; // skip '['
    skip_whitespace(chars, idx);
    let mut elements = Vec::new();

    if *idx < chars.len() && chars[*idx] == ']' {
        *idx += 1;
        return Ok(JsonValue::Array(elements));
    }

    loop {
        let val = parse_value(chars, idx)?;
        elements.push(val);
        skip_whitespace(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated array".to_string());
        }
        if chars[*idx] == ',' {
            *idx += 1;
            skip_whitespace(chars, idx);
        } else if chars[*idx] == ']' {
            *idx += 1;
            break;
        } else {
            return Err(format!("Expected ',' or ']' in array at position {}", idx));
        }
    }

    Ok(JsonValue::Array(elements))
}

fn parse_object(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    *idx += 1; // skip '{'
    skip_whitespace(chars, idx);
    let mut entries = Vec::new();

    if *idx < chars.len() && chars[*idx] == '}' {
        *idx += 1;
        return Ok(JsonValue::Object(entries));
    }

    loop {
        skip_whitespace(chars, idx);
        if *idx >= chars.len() || chars[*idx] != '"' {
            return Err(format!("Expected string key in object at position {}", idx));
        }
        let key = parse_string(chars, idx)?;
        skip_whitespace(chars, idx);
        if *idx >= chars.len() || chars[*idx] != ':' {
            return Err(format!(
                "Expected ':' after key '{}' at position {}",
                key, idx
            ));
        }
        *idx += 1; // skip ':'
        let val = parse_value(chars, idx)?;
        entries.push((key, val));

        skip_whitespace(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated object".to_string());
        }
        if chars[*idx] == ',' {
            *idx += 1;
            skip_whitespace(chars, idx);
        } else if chars[*idx] == '}' {
            *idx += 1;
            break;
        } else {
            return Err(format!(
                "Expected ',' or '}}' in object at position {}",
                idx
            ));
        }
    }

    Ok(JsonValue::Object(entries))
}

fn format_pretty(val: &JsonValue, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match val {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Number(n) => {
            if n.fract() == 0.0
                && !n.is_infinite()
                && !n.is_nan()
                && *n >= (i64::MIN as f64)
                && *n <= (i64::MAX as f64)
            {
                out.push_str(&format!("{}", *n as i64));
            } else {
                out.push_str(&format!("{}", n));
            }
        }
        JsonValue::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        JsonValue::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
            } else {
                out.push_str("[\n");
                for (i, elem) in arr.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    format_pretty(elem, indent + 1, out);
                    if i + 1 < arr.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
        }
        JsonValue::Object(obj) => {
            if obj.is_empty() {
                out.push_str("{}");
            } else {
                out.push_str("{\n");
                for (i, (k, v)) in obj.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    out.push('"');
                    out.push_str(k);
                    out.push_str("\": ");
                    format_pretty(v, indent + 1, out);
                    if i + 1 < obj.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
    }
}
