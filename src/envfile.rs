use std::fs;
use std::io;
use std::path::Path;

use crate::error::SealedError;

pub fn read_var(path: &Path, var: &str) -> Result<Option<String>, SealedError> {
    let content = fs::read_to_string(path).map_err(|e| {
        SealedError::EnvFile(format!("failed to read env file {}: {}", path.display(), e))
    })?;

    let mut last = None;

    for line in content.lines() {
        if let Some(parsed) = parse_var_line(line)
            && parsed.key == var
        {
            last = Some(parsed.value);
        }
    }

    Ok(last)
}

pub fn upsert_var(path: &Path, var: &str, value: &str) -> Result<(), SealedError> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(SealedError::EnvFile(format!(
                "failed to read env file {}: {}",
                path.display(),
                e
            )));
        }
    };

    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut replaced = false;

    for line in &mut lines {
        if let Some(parsed) = parse_var_line(line)
            && parsed.key == var
        {
            let mut new_line = String::new();
            new_line.push_str(&parsed.leading_ws);
            if parsed.export_prefix {
                new_line.push_str("export ");
            }
            new_line.push_str(var);
            new_line.push('=');
            new_line.push_str(value);
            *line = new_line;
            replaced = true;
        }
    }

    if !replaced {
        lines.push(format!("{}={}", var, value));
    }

    let mut new_content = lines.join("\n");
    new_content.push('\n');

    fs::write(path, new_content).map_err(|e| {
        SealedError::EnvFile(format!(
            "failed to write env file {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(())
}

fn parse_var_line(line: &str) -> Option<ParsedLine> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let leading_ws = line[..line.len() - trimmed.len()].to_string();
    let (export_prefix, rest) = if let Some(stripped) = trimmed.strip_prefix("export ") {
        (true, stripped)
    } else {
        (false, trimmed)
    };

    let eq = rest.find('=')?;
    let key = rest[..eq].trim_end();

    if key.is_empty() {
        return None;
    }

    let value = rest[eq + 1..].to_string();

    Some(ParsedLine {
        leading_ws,
        export_prefix,
        key: key.to_string(),
        value,
    })
}

struct ParsedLine {
    leading_ws: String,
    export_prefix: bool,
    key: String,
    value: String,
}
