use serde::Serialize;
use std::{
    collections::HashSet,
    env,
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub kind: String,
    pub command: String,
    pub version: Option<String>,
    pub executable: Option<String>,
    pub available: bool,
    pub issue: Option<String>,
    pub project: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub command: String,
    pub version: Option<String>,
    pub executable: Option<String>,
    pub available: bool,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceDiagnosis {
    pub project_root: Option<String>,
    pub projects: Vec<ProjectTopology>,
    pub runtimes: Vec<RuntimeInfo>,
    pub tools: Vec<ToolInfo>,
    pub path_issues: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkCheck {
    pub layer: String,
    pub name: String,
    pub state: String,
    pub detail: String,
    pub latency_ms: Option<u128>,
    pub healthy: bool,
    pub warning: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiDiagnosis {
    pub title: String,
    pub priority: String,
    pub evidence: Vec<String>,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectTopology {
    pub name: String,
    pub root: String,
    pub runtimes: Vec<String>,
    pub state: String,
    pub issue: Option<String>,
}

#[derive(Debug, Error)]
pub enum DiagnosticsError {
    #[error("diagnostics command failed: {0}")]
    Command(String),
}

pub fn diagnose(start: impl AsRef<Path>) -> WorkspaceDiagnosis {
    let start = start.as_ref();
    let project_root = find_project_root(start);
    let project = project_root
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let runtime_defs = [
        ("Node.js", "node", "--version"),
        ("Python", "python", "--version"),
        ("Java", "java", "-version"),
        ("Go", "go", "version"),
        (".NET", "dotnet", "--version"),
    ];
    let tool_defs = [
        ("Git", "git", "--version"),
        ("npm", "npm", "--version"),
        ("pnpm", "pnpm", "--version"),
        ("Docker", "docker", "--version"),
        ("WSL", "wsl", "--version"),
    ];
    let runtimes = runtime_defs
        .into_iter()
        .map(|(kind, command, arg)| probe_runtime(kind, command, arg, project.clone()))
        .collect::<Vec<_>>();
    let tools = tool_defs
        .into_iter()
        .map(|(name, command, arg)| probe_tool(name, command, arg))
        .collect::<Vec<_>>();
    let mut issues = Vec::new();
    issues.extend(runtimes.iter().filter_map(|item| item.issue.clone()));
    issues.extend(tools.iter().filter_map(|item| item.issue.clone()));
    let projects = project_root
        .clone()
        .into_iter()
        .map(|root| {
            let runtimes_for_project = runtimes
                .iter()
                .filter(|runtime| runtime.available)
                .map(|runtime| runtime.kind.clone())
                .collect::<Vec<_>>();
            let issue = runtimes
                .iter()
                .filter_map(|runtime| runtime.issue.clone())
                .next();
            ProjectTopology {
                name: root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("工作区")
                    .into(),
                root: root.to_string_lossy().into_owned(),
                runtimes: runtimes_for_project,
                state: if issue.is_some() {
                    "关注".into()
                } else {
                    "就绪".into()
                },
                issue,
            }
        })
        .collect();
    WorkspaceDiagnosis {
        project_root: project,
        projects,
        runtimes,
        tools,
        path_issues: path_issues(),
        issues,
    }
}

pub fn network_diagnose() -> Vec<NetworkCheck> {
    let mut checks = Vec::new();
    let adapter = Command::new(if cfg!(windows) {
        "ipconfig"
    } else {
        "ifconfig"
    })
    .output();
    checks.push(
        if adapter
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            ok("网络适配器", "本机网卡", "适配器信息读取成功", None)
        } else {
            fail("网络适配器", "本机网卡", "无法读取适配器信息")
        },
    );
    checks.push(tcp_check("DNS", "域名解析", "example.com:443"));
    checks.push(tcp_check("外网", "HTTPS 连接", "registry.npmjs.org:443"));
    checks.push(tcp_check(
        "外网",
        "Docker Registry",
        "registry-1.docker.io:443",
    ));
    let proxy = env::var("HTTPS_PROXY")
        .or_else(|_| env::var("https_proxy"))
        .ok();
    checks.push(if let Some(proxy) = proxy {
        ok("代理", "HTTPS_PROXY", &format!("已配置：{}", proxy), None)
    } else {
        NetworkCheck {
            layer: "代理".into(),
            name: "HTTPS_PROXY".into(),
            state: "未配置".into(),
            detail: "未检测到 HTTPS 代理环境变量".into(),
            latency_ms: None,
            healthy: true,
            warning: true,
        }
    });
    checks
}

fn tcp_check(layer: &str, name: &str, target: &str) -> NetworkCheck {
    let started = Instant::now();
    let address = target
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next());
    let Some(address) = address else {
        return fail(layer, name, &format!("无法解析 {target}"));
    };
    match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
        Ok(_) => ok(
            layer,
            name,
            &format!("{target} 可连接"),
            Some(started.elapsed().as_millis()),
        ),
        Err(error) => fail(layer, name, &format!("{target} 连接失败：{error}")),
    }
}

fn ok(layer: &str, name: &str, detail: &str, latency_ms: Option<u128>) -> NetworkCheck {
    NetworkCheck {
        layer: layer.into(),
        name: name.into(),
        state: "正常".into(),
        detail: detail.into(),
        latency_ms,
        healthy: true,
        warning: false,
    }
}
fn fail(layer: &str, name: &str, detail: &str) -> NetworkCheck {
    NetworkCheck {
        layer: layer.into(),
        name: name.into(),
        state: "异常".into(),
        detail: detail.into(),
        latency_ms: None,
        healthy: false,
        warning: true,
    }
}

pub fn local_ai_diagnose(workspace: &WorkspaceDiagnosis, network: &[NetworkCheck]) -> AiDiagnosis {
    let mut evidence = workspace.issues.iter().take(5).cloned().collect::<Vec<_>>();
    evidence.extend(
        network
            .iter()
            .filter(|check| !check.healthy)
            .map(|check| format!("{}：{}", check.name, check.detail))
            .take(5),
    );
    let priority = if evidence.is_empty() {
        "低"
    } else if evidence
        .iter()
        .any(|item| item.contains("网络") || item.contains("连接"))
    {
        "高"
    } else {
        "中"
    };
    let actions = if evidence.is_empty() {
        vec!["继续保持当前环境，定期复测网络和工具链。".into()]
    } else {
        vec![
            "先修复异常网络或缺失工具，再重新执行诊断。".into(),
            "确认项目使用的 Runtime 版本与团队要求一致。".into(),
        ]
    };
    AiDiagnosis {
        title: if evidence.is_empty() {
            "工作站环境正常".into()
        } else {
            "发现需要关注的工作站问题".into()
        },
        priority: priority.into(),
        evidence,
        actions,
    }
}

fn probe_runtime(kind: &str, command: &str, arg: &str, project: Option<String>) -> RuntimeInfo {
    let result = probe(command, arg);
    RuntimeInfo {
        kind: kind.into(),
        command: command.into(),
        version: result.version,
        executable: result.executable,
        available: result.available,
        issue: result.issue,
        project,
    }
}

fn probe_tool(name: &str, command: &str, arg: &str) -> ToolInfo {
    let result = probe(command, arg);
    ToolInfo {
        name: name.into(),
        command: command.into(),
        version: result.version,
        executable: result.executable,
        available: result.available,
        issue: result.issue,
    }
}

struct ProbeResult {
    version: Option<String>,
    executable: Option<String>,
    available: bool,
    issue: Option<String>,
}

fn probe(command: &str, arg: &str) -> ProbeResult {
    let executable = which(command);
    let Some(executable_path) = executable.clone() else {
        return ProbeResult {
            version: None,
            executable: None,
            available: false,
            issue: Some(format!("未找到 {command}")),
        };
    };
    match Command::new(command).arg(arg).output() {
        Ok(output) if output.status.success() || !output.stderr.is_empty() => {
            let text = String::from_utf8_lossy(if output.stdout.is_empty() {
                &output.stderr
            } else {
                &output.stdout
            })
            .trim()
            .to_string();
            ProbeResult {
                version: Some(text.lines().next().unwrap_or_default().to_string()),
                executable: Some(executable_path),
                available: true,
                issue: None,
            }
        }
        Ok(output) => ProbeResult {
            version: None,
            executable: Some(executable_path),
            available: false,
            issue: Some(format!("{command} 执行失败（{}）", output.status)),
        },
        Err(error) => ProbeResult {
            version: None,
            executable: Some(executable_path),
            available: false,
            issue: Some(format!("{command} 无法执行：{error}")),
        },
    }
}

fn which(command: &str) -> Option<String> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
        #[cfg(windows)]
        for extension in [".exe", ".cmd", ".bat"] {
            let candidate = directory.join(format!("{command}{extension}"));
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.canonicalize().ok()?;
    if current.is_file() {
        current.pop();
    }
    loop {
        if [
            "package.json",
            "pyproject.toml",
            "go.mod",
            "pom.xml",
            "Cargo.toml",
        ]
        .iter()
        .any(|name| current.join(name).is_file())
            || current.join(".git").is_dir()
        {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn path_issues() -> Vec<String> {
    let Some(raw) = env::var_os("PATH") else {
        return vec!["PATH 未设置".into()];
    };
    let mut seen = HashSet::new();
    env::split_paths(&raw)
        .filter_map(|path| {
            if path.is_dir() {
                None
            } else {
                Some(path.to_string_lossy().into_owned())
            }
        })
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_project_root_from_nested_directory() {
        let root = env::current_dir().unwrap();
        let diagnosis = diagnose(&root);
        assert!(diagnosis.project_root.is_some());
        assert!(!diagnosis.tools.is_empty());
    }

    #[test]
    fn builds_local_ai_summary_without_network() {
        let workspace = WorkspaceDiagnosis {
            project_root: None,
            projects: Vec::new(),
            runtimes: Vec::new(),
            tools: Vec::new(),
            path_issues: Vec::new(),
            issues: vec!["未找到 node".into()],
        };
        let result = local_ai_diagnose(&workspace, &[]);
        assert_eq!(result.priority, "中");
        assert!(!result.actions.is_empty());
    }
}
