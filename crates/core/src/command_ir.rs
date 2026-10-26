use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedCommand {
    pub raw: String,
    pub shell: CommandShell,
    pub executable: Option<String>,
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub target_paths: Vec<String>,
    pub network_targets: Vec<String>,
    pub operators: Vec<String>,
    pub nested_commands: Vec<ParsedCommand>,
    pub truncated: bool,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum CommandShell {
    PowerShell,
    Cmd,
    Bash,
    Wsl,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticFact {
    pub kind: String,
    pub value: String,
}

const MAX_COMMAND_CHARS: usize = 8192;

pub fn parse_command(raw: &str) -> ParsedCommand {
    let mut input = raw.trim().to_string();
    let truncated = input.chars().count() > MAX_COMMAND_CHARS;
    if truncated {
        input = input.chars().take(MAX_COMMAND_CHARS).collect();
    }
    let tokens = tokenize(&input);
    let executable = tokens.first().cloned();
    let subcommand = tokens.get(1).filter(|token| !is_option(token)).cloned();
    let shell = infer_shell(executable.as_deref(), &input);
    let operators = tokens
        .iter()
        .filter(|token| matches!(token.as_str(), "|" | ">" | ">>" | "&&" | "||" | ";"))
        .cloned()
        .collect::<Vec<_>>();
    let network_targets = extract_urls(&input);
    let target_paths = tokens
        .iter()
        .filter(|token| looks_like_path(token))
        .cloned()
        .collect::<Vec<_>>();
    let nested_commands = nested_command_inputs(&tokens)
        .into_iter()
        .map(|nested| parse_command(&nested))
        .collect();
    ParsedCommand {
        raw: input,
        shell,
        executable,
        subcommand,
        args: tokens.into_iter().skip(1).collect(),
        target_paths,
        network_targets,
        operators,
        nested_commands,
        truncated,
        parse_error: None,
    }
}

pub fn semantic_facts(command: &ParsedCommand) -> Vec<SemanticFact> {
    let mut facts = Vec::new();
    if let Some(executable) = &command.executable {
        facts.push(fact("executable", executable));
    }
    if let Some(subcommand) = &command.subcommand {
        facts.push(fact("subcommand", subcommand));
    }
    for path in &command.target_paths {
        facts.push(fact("target_path", path));
    }
    for target in &command.network_targets {
        facts.push(fact("network_target", target));
    }
    for nested in &command.nested_commands {
        facts.extend(semantic_facts(nested));
    }
    facts
}

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if quote.is_none() && ch.is_whitespace() {
            push_token(&mut tokens, &mut current);
            continue;
        }
        if quote.is_none() && matches!(ch, '|' | '>' | ';') {
            push_token(&mut tokens, &mut current);
            if ch == '>' && chars.peek() == Some(&'>') {
                chars.next();
                tokens.push(">>".into());
            } else if ch == '|' && chars.peek() == Some(&'|') {
                chars.next();
                tokens.push("||".into());
            } else {
                tokens.push(ch.to_string());
            }
            continue;
        }
        if quote.is_none() && ch == '&' && chars.peek() == Some(&'&') {
            chars.next();
            push_token(&mut tokens, &mut current);
            tokens.push("&&".into());
            continue;
        }
        if matches!(ch, '"' | '\'') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\\' {
            if let Some(next) = chars.next() {
                current.push(next);
            }
            continue;
        }
        current.push(ch);
    }
    push_token(&mut tokens, &mut current);
    tokens
}

fn push_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

fn infer_shell(executable: Option<&str>, raw: &str) -> CommandShell {
    let executable = executable.unwrap_or_default().to_ascii_lowercase();
    if executable.contains("powershell") || executable == "pwsh" {
        CommandShell::PowerShell
    } else if executable == "cmd" || executable == "cmd.exe" {
        CommandShell::Cmd
    } else if executable == "bash" || executable == "sh" {
        CommandShell::Bash
    } else if executable == "wsl" {
        CommandShell::Wsl
    } else if raw.to_ascii_lowercase().contains("powershell -command") {
        CommandShell::PowerShell
    } else {
        CommandShell::Unknown
    }
}

fn nested_command_inputs(tokens: &[String]) -> Vec<String> {
    let mut nested = Vec::new();
    for pair in tokens.windows(2) {
        let flag = pair[0].to_ascii_lowercase();
        if matches!(
            flag.as_str(),
            "-c" | "/c" | "-command" | "-encodedcommand" | "-e"
        ) {
            nested.push(pair[1].clone());
        }
    }
    nested
}

fn extract_urls(input: &str) -> Vec<String> {
    Regex::new(r#"https?://[^\s"']+"#)
        .expect("static url regex")
        .find_iter(input)
        .map(|mat| mat.as_str().to_string())
        .collect()
}

fn looks_like_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains('/')
        || lower.contains('\\')
        || lower.starts_with('.')
        || lower.ends_with(".env")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
}

fn is_option(token: &str) -> bool {
    token.starts_with('-') || token.starts_with('/')
}

fn fact(kind: &str, value: &str) -> SemanticFact {
    SemanticFact {
        kind: kind.into(),
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_checkout_branch_as_safe_structure() {
        let parsed = parse_command("git checkout -b feature/audit");
        assert_eq!(parsed.executable.as_deref(), Some("git"));
        assert_eq!(parsed.subcommand.as_deref(), Some("checkout"));
        assert!(parsed.args.contains(&"-b".into()));
    }

    #[test]
    fn parses_pipes_redirects_urls_and_paths() {
        let parsed = parse_command("curl https://example.test/a | tee ./out.log");
        assert!(parsed.operators.contains(&"|".into()));
        assert_eq!(parsed.network_targets[0], "https://example.test/a");
        assert!(parsed.target_paths.contains(&"./out.log".into()));
    }

    #[test]
    fn parses_nested_shell_command() {
        let parsed = parse_command("bash -c \"rm -rf ./target\"");
        assert_eq!(parsed.shell, CommandShell::Bash);
        assert_eq!(parsed.nested_commands[0].executable.as_deref(), Some("rm"));
    }

    #[test]
    fn parses_powershell_command() {
        let parsed = parse_command("powershell -Command \"Remove-Item -Recurse .\\tmp\"");
        assert_eq!(parsed.shell, CommandShell::PowerShell);
        assert_eq!(
            parsed.nested_commands[0].executable.as_deref(),
            Some("Remove-Item")
        );
    }

    #[test]
    fn truncates_overlong_command_without_crash() {
        let parsed = parse_command(&"a".repeat(9000));
        assert!(parsed.truncated);
        assert_eq!(parsed.raw.len(), 8192);
    }
}
