use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("platform capability is unavailable: {0}")]
    Unsupported(String),
    #[error("platform collection failed: {0}")]
    Collection(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum CapabilityState {
    Available,
    PermissionRequired,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformCapabilities {
    pub system_metrics: CapabilityState,
    pub process_list: CapabilityState,
    pub process_termination: CapabilityState,
    pub listening_ports: CapabilityState,
    pub command_line: CapabilityState,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemSnapshot {
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disks: Vec<DiskSnapshot>,
    pub processes: Vec<ProcessSnapshot>,
    pub ports: Vec<PortSnapshot>,
    pub capabilities: PlatformCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskSnapshot {
    pub name: String,
    pub mount_point: String,
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub cpu_usage: f32,
    pub memory: u64,
    pub protected: bool,
    pub protection_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortSnapshot {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub listening: bool,
}

#[async_trait]
pub trait SystemSampler: Send + Sync {
    async fn snapshot(&self) -> Result<SystemSnapshot, PlatformError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessOperationResult {
    pub success: bool,
    pub pid: u32,
    pub process_name: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStartRecord {
    pub pid: u32,
    pub process_name: String,
}

#[async_trait]
pub trait ProcessService: Send + Sync {
    async fn terminate(
        &self,
        pid: u32,
        expected_name: &str,
    ) -> Result<ProcessOperationResult, PlatformError>;
}

#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod windows {
    use super::*;

    pub struct WindowsSystemSampler;
    pub struct WindowsProcessService;
    pub struct WindowsProcessEventSource;

    impl WindowsSystemSampler {
        pub fn new() -> Self {
            Self
        }
    }

    impl WindowsProcessService {
        pub fn new() -> Self {
            Self
        }
    }

    impl WindowsProcessEventSource {
        pub fn start() -> Self {
            Self
        }
        pub fn is_active(&self) -> bool {
            false
        }
        pub fn drain(&self) -> Vec<ProcessStartRecord> {
            Vec::new()
        }
    }

    #[async_trait]
    impl SystemSampler for WindowsSystemSampler {
        async fn snapshot(&self) -> Result<SystemSnapshot, PlatformError> {
            Err(PlatformError::Unsupported(
                "Windows adapter on non-Windows host".into(),
            ))
        }
    }

    #[async_trait]
    impl ProcessService for WindowsProcessService {
        async fn terminate(
            &self,
            _pid: u32,
            _expected_name: &str,
        ) -> Result<ProcessOperationResult, PlatformError> {
            Err(PlatformError::Unsupported(
                "Windows process service on non-Windows host".into(),
            ))
        }
    }
}
