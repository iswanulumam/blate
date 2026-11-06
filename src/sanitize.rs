//! Makes untrusted process data safe to display.
//!
//! Process names, command lines, and paths are chosen by the processes being
//! observed. Printed raw, they could send escape sequences to the operator's
//! terminal, forge output lines, or reorder text with Unicode controls.

use std::fmt::Write as _;

const REDACTED: &[u8] = b"[REDACTED]";

/// Lowercase substrings that mark a name as holding a secret.
const SENSITIVE_NAMES: &[&[u8]] = &[
    b"token",
    b"secret",
    b"passw",
    b"passphrase",
    b"apikey",
    b"api-key",
    b"api_key",
    b"credential",
    b"auth",
    b"private-key",
    b"private_key",
    b"bearer",
    b"cookie",
];

/// Prefixes of widely used credential formats.
const TOKEN_PREFIXES: &[&[u8]] = &[
    b"sk-",
    b"ghp_",
    b"gho_",
    b"ghs_",
    b"github_pat_",
    b"glpat-",
    b"xoxb-",
    b"xoxp-",
    b"AKIA",
];
const MIN_TOKEN_LEN: usize = 20;

/// Escapes bytes so that they print as a single inert run of text.
///
/// Escaping is unambiguous: backslashes are doubled, so an escape sequence in
/// the output always comes from Blate rather than from the process.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                out.push_str("\\\\");
            } else if is_unsafe_char(c) {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            } else {
                out.push(c);
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    out
}

/// Escapes a value for a whitespace-separated table column.
pub fn escape_field(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_owned();
    }
    escape(bytes).replace(' ', "\\u{20}")
}

fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Zero-width, line separator, and bidirectional controls.
            '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// Formats arguments on one line, escaped and with argument boundaries kept.
pub fn format_args_line(args: &[Vec<u8>]) -> String {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        let text = escape(arg);
        if text.is_empty() || text.contains([' ', '"']) {
            parts.push(format!("\"{}\"", text.replace('"', "\\\"")));
        } else {
            parts.push(text);
        }
    }
    parts.join(" ")
}

/// Replaces likely secrets in command-line arguments.
///
/// This is best effort, and it prefers hiding too much over hiding too little.
/// It reduces accidental exposure in output and logs but cannot recognize every
/// secret, so its output must still be treated as sensitive.
pub fn redact_args(args: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(args.len());
    let mut value_is_secret = false;
    for arg in args {
        if value_is_secret && !arg.starts_with(b"-") {
            out.push(REDACTED.to_vec());
            value_is_secret = false;
            continue;
        }
        value_is_secret = arg.starts_with(b"-") && !arg.contains(&b'=') && is_sensitive(arg);
        out.push(redact_arg(arg));
    }
    out
}

fn redact_arg(arg: &[u8]) -> Vec<u8> {
    // A shell snippet or free text passed as one argument, such as `sh -c`.
    if arg.iter().any(u8::is_ascii_whitespace) && is_sensitive(arg) {
        return REDACTED.to_vec();
    }
    if looks_like_token(arg) {
        return REDACTED.to_vec();
    }
    // `--name=value`, `NAME=value`, and `Name: value`.
    for separator in [b'=', b':'] {
        if let Some(index) = arg.iter().position(|b| *b == separator) {
            let (name, value) = (&arg[..index], &arg[index + 1..]);
            if is_sensitive(name) || looks_like_token(value) {
                return [&arg[..=index], REDACTED].concat();
            }
        }
    }
    redact_url_credentials(arg)
}

fn is_sensitive(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_NAMES
        .iter()
        .any(|word| lower.windows(word.len()).any(|window| window == *word))
}

fn looks_like_token(value: &[u8]) -> bool {
    value.len() >= MIN_TOKEN_LEN
        && TOKEN_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

/// Replaces the `user:password` part of every URL in `arg`.
fn redact_url_credentials(arg: &[u8]) -> Vec<u8> {
    const SCHEME_END: &[u8] = b"://";
    let mut out = Vec::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(scheme) = rest
        .windows(SCHEME_END.len())
        .position(|window| window == SCHEME_END)
    {
        let authority_start = scheme + SCHEME_END.len();
        out.extend_from_slice(&rest[..authority_start]);
        rest = &rest[authority_start..];
        let authority_len = rest
            .iter()
            .position(|b| matches!(b, b'/' | b'?' | b'#') || b.is_ascii_whitespace())
            .unwrap_or(rest.len());
        if let Some(at) = rest[..authority_len].iter().rposition(|b| *b == b'@') {
            out.extend_from_slice(REDACTED);
            rest = &rest[at..];
        }
    }
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(args: &[&str]) -> Vec<String> {
        let args: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
        redact_args(&args)
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect()
    }

    #[test]
    fn neutralizes_terminal_escape_sequences() {
        let output = escape(b"evil\x1b]0;owned\x07\x1b[2J\r\nfake");
        assert_eq!(
            output,
            "evil\\u{1b}]0;owned\\u{7}\\u{1b}[2J\\u{d}\\u{a}fake"
        );
        assert!(!output.chars().any(char::is_control));
    }

    #[test]
    fn neutralizes_c1_controls_and_unicode_tricks() {
        assert_eq!(escape("a\u{9b}b".as_bytes()), "a\\u{9b}b");
        assert_eq!(escape("a\u{202e}b".as_bytes()), "a\\u{202e}b");
        assert_eq!(escape("a\u{200b}b".as_bytes()), "a\\u{200b}b");
    }

    #[test]
    fn escaping_is_unambiguous() {
        assert_eq!(escape(b"\xff"), "\\xff");
        assert_eq!(escape(b"\\xff"), "\\\\xff");
        assert_eq!(escape("héllo".as_bytes()), "héllo");
    }

    #[test]
    fn table_fields_cannot_forge_columns() {
        assert_eq!(escape_field(b"a b"), "a\\u{20}b");
        assert_eq!(escape_field(b""), "-");
    }

    #[test]
    fn keeps_argument_boundaries_visible() {
        let args = vec![
            b"echo".to_vec(),
            b"a b".to_vec(),
            b"".to_vec(),
            b"c".to_vec(),
        ];
        assert_eq!(format_args_line(&args), r#"echo "a b" "" c"#);
    }

    #[test]
    fn redacts_named_values() {
        assert_eq!(redact(&["--token=abc"]), ["--token=[REDACTED]"]);
        assert_eq!(redact(&["--API-KEY", "abc"]), ["--API-KEY", "[REDACTED]"]);
        assert_eq!(redact(&["DB_PASSWORD=abc"]), ["DB_PASSWORD=[REDACTED]"]);
        assert_eq!(
            redact(&["-H", "Authorization: Bearer abc"]),
            ["-H", "[REDACTED]"]
        );
        assert_eq!(redact(&["cookie:abc"]), ["cookie:[REDACTED]"]);
    }

    #[test]
    fn a_following_flag_is_not_treated_as_the_secret() {
        assert_eq!(redact(&["--token", "--verbose"]), ["--token", "--verbose"]);
    }

    #[test]
    fn redacts_recognizable_tokens_without_a_name() {
        let token = "ghp_0123456789abcdefghij";
        assert_eq!(redact(&[token]), ["[REDACTED]"]);
        assert_eq!(
            redact(&[&format!("--value={token}")]),
            ["--value=[REDACTED]"]
        );
    }

    #[test]
    fn redacts_url_credentials_and_keeps_the_host() {
        assert_eq!(
            redact(&["https://me:pw@example.com/x", "--u=ftp://a@b/"]),
            [
                "https://[REDACTED]@example.com/x",
                "--u=ftp://[REDACTED]@b/"
            ]
        );
    }

    #[test]
    fn redacts_secrets_inside_shell_snippets() {
        assert_eq!(
            redact(&["sh", "-c", "tool --token abc"]),
            ["sh", "-c", "[REDACTED]"]
        );
    }

    #[test]
    fn leaves_ordinary_arguments_alone() {
        let args = [
            "node",
            "/usr/lib/app/cli.js",
            "--port=8080",
            "https://example.com:443/a@b",
            "sk-short",
        ];
        assert_eq!(redact(&args), args);
    }
}
