use crate::{
    CapabilityState, DiskSnapshot, PlatformCapabilities, PlatformError, PortSnapshot,
    ProcessOperationResult, ProcessService, ProcessSnapshot, ProcessStartRecord, SystemSampler,
    SystemSnapshot,
};
use async_trait::async_trait;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use serde::Deserialize;
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
    Arc,
};
use std::time::{Duration, Instant};
use sysinfo::{Disks, Pid, ProcessesToUpdate, System};

pub struct WindowsSystemSampler {
    system: Mutex<System>,
    process_system: Mutex<System>,
    disks: Mutex<Option<Cached<Vec<DiskSnapshot>>>>,
    ports: Mutex<Option<Cached<Vec<PortSnapshot>>>>,
    processes: Mutex<Option<Cached<Vec<ProcessSnapshot>>>>,
    process_refresh_interval: Mutex<Duration>,
    port_refresh_interval: Mutex<Duration>,
}

struct Cached<T> {
    collected_at: Instant,
    value: T,
}

pub struct WindowsProcessService;

pub struct WindowsProcessEventSource {
    receiver: Receiver<ProcessStartRecord>,
    active: Arc<AtomicBool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Win32_ProcessStartTrace")]
#[serde(rename_all = "PascalCase")]
struct ProcessStartTrace {
    process_id: u32,
    process_name: String,
}

impl WindowsProcessEventSource {
    pub fn start() -> Self {
        let (sender, receiver) = mpsc::channel();
        let active = Arc::new(AtomicBool::new(false));
        let thread_active = Arc::clone(&active);
        std::thread::spawn(move || {
            let Ok(com) = wmi::COMLibrary::new() else {
                return;
            };
            let Ok(connection) = wmi::WMIConnection::new(com) else {
                return;
            };
            let Ok(events) = connection.notification::<ProcessStartTrace>() else {
                return;
            };
            thread_active.store(true, Ordering::Release);
            for event in events {
                let Ok(event) = event else {
                    continue;
                };
                if sender
                    .send(ProcessStartRecord {
                        pid: event.process_id,
                        process_name: event.process_name,
                    })
                    .is_err()
                {
                    break;
                }
            }
            thread_active.store(false, Ordering::Release);
        });
        Self { receiver, active }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn drain(&self) -> Vec<ProcessStartRecord> {
        let mut records = Vec::new();
        while let Ok(record) = self.receiver.try_recv() {
            records.push(record);
        }
        records
    }
}

impl Default for WindowsProcessService {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsProcessService {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsSystemSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsSystemSampler {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_usage();
        system.refresh_memory();
        let mut process_system = System::new_all();
        process_system.refresh_processes(ProcessesToUpdate::All, true);
        let initial_processes = process_system
            .processes()
            .values()
            .map(process_snapshot)
            .collect();
        let initial_ports = collect_ports();
        Self {
            system: Mutex::new(system),
            process_system: Mutex::new(process_system),
            disks: Mutex::new(None),
            ports: Mutex::new(Some(Cached {
                collected_at: Instant::now(),
                value: initial_ports,
            })),
            processes: Mutex::new(Some(Cached {
                collected_at: Instant::now(),
                value: initial_processes,
            })),
            process_refresh_interval: Mutex::new(Duration::from_secs(30)),
            port_refresh_interval: Mutex::new(Duration::from_secs(30)),
        }
    }

    pub fn set_process_refresh_interval(&self, interval: Duration) -> Result<(), PlatformError> {
        let mut current = self.process_refresh_interval.lock().map_err(|_| {
            PlatformError::Collection("process refresh interval lock poisoned".into())
        })?;
        if *current == interval {
            return Ok(());
        }
        *current = interval;
        Ok(())
    }

    pub fn set_port_refresh_interval(&self, interval: Duration) -> Result<(), PlatformError> {
        *self.port_refresh_interval.lock().map_err(|_| {
            PlatformError::Collection("port refresh interval lock poisoned".into())
        })? = interval;
        Ok(())
    }

    pub fn refresh_processes_if_due(&self) -> Result<bool, PlatformError> {
        let refresh_interval = *self.process_refresh_interval.lock().map_err(|_| {
            PlatformError::Collection("process refresh interval lock poisoned".into())
        })?;
        if self
            .processes
            .lock()
            .map_err(|_| PlatformError::Collection("process cache lock poisoned".into()))?
            .as_ref()
            .is_some_and(|cached| cached.collected_at.elapsed() < refresh_interval)
        {
            return Ok(false);
        }
        let value = {
            let mut system = self
                .process_system
                .lock()
                .map_err(|_| PlatformError::Collection("process sampler lock poisoned".into()))?;
            system.refresh_processes(ProcessesToUpdate::All, true);
            system.processes().values().map(process_snapshot).collect()
        };
        *self
            .processes
            .lock()
            .map_err(|_| PlatformError::Collection("process cache lock poisoned".into()))? =
            Some(Cached {
                collected_at: Instant::now(),
                value,
            });
        Ok(true)
    }

    pub fn refresh_ports_if_due(&self) -> Result<bool, PlatformError> {
        let refresh_interval = *self
            .port_refresh_interval
            .lock()
            .map_err(|_| PlatformError::Collection("port refresh interval lock poisoned".into()))?;
        if self
            .ports
            .lock()
            .map_err(|_| PlatformError::Collection("port cache lock poisoned".into()))?
            .as_ref()
            .is_some_and(|cached| cached.collected_at.elapsed() < refresh_interval)
        {
            return Ok(false);
        }
        let value = collect_ports();
        *self
            .ports
            .lock()
            .map_err(|_| PlatformError::Collection("port cache lock poisoned".into()))? =
            Some(Cached {
                collected_at: Instant::now(),
                value,
            });
        Ok(true)
    }
}

#[async_trait]
impl SystemSampler for WindowsSystemSampler {
    async fn snapshot(&self) -> Result<SystemSnapshot, PlatformError> {
        let (cpu_usage, memory_used, memory_total) = {
            let mut system = self
                .system
                .lock()
                .map_err(|_| PlatformError::Collection("system sampler lock poisoned".into()))?;
            system.refresh_cpu_usage();
            system.refresh_memory();
            (
                system.global_cpu_usage(),
                system.used_memory(),
                system.total_memory(),
            )
        };
        let processes = self.cached_processes()?;
        let disks = self.cached_disks()?;
        let mut ports = self.cached_ports()?;
        attach_port_process_names(&mut ports, &processes);
        Ok(SystemSnapshot {
            cpu_usage,
            memory_used,
            memory_total,
            disks,
            processes,
            ports,
            capabilities: PlatformCapabilities {
                system_metrics: CapabilityState::Available,
                process_list: CapabilityState::Available,
                process_termination: CapabilityState::Available,
                listening_ports: CapabilityState::Available,
                command_line: CapabilityState::PermissionRequired,
            },
        })
    }
}

impl WindowsSystemSampler {
    fn cached_processes(&self) -> Result<Vec<ProcessSnapshot>, PlatformError> {
        Ok(self
            .processes
            .lock()
            .map_err(|_| PlatformError::Collection("process cache lock poisoned".into()))?
            .as_ref()
            .map(|cached| cached.value.clone())
            .unwrap_or_default())
    }

    fn cached_disks(&self) -> Result<Vec<DiskSnapshot>, PlatformError> {
        let mut cache = self
            .disks
            .lock()
            .map_err(|_| PlatformError::Collection("disk cache lock poisoned".into()))?;
        if let Some(cached) = cache.as_ref() {
            if cached.collected_at.elapsed() < Duration::from_secs(10) {
                return Ok(cached.value.clone());
            }
        }
        let value = Disks::new_with_refreshed_list()
            .list()
            .iter()
            .map(|disk| DiskSnapshot {
                name: disk.name().to_string_lossy().into_owned(),
                mount_point: disk.mount_point().to_string_lossy().into_owned(),
                total: disk.total_space(),
                available: disk.available_space(),
            })
            .collect::<Vec<_>>();
        *cache = Some(Cached {
            collected_at: Instant::now(),
            value: value.clone(),
        });
        Ok(value)
    }

    fn cached_ports(&self) -> Result<Vec<PortSnapshot>, PlatformError> {
        Ok(self
            .ports
            .lock()
            .map_err(|_| PlatformError::Collection("port cache lock poisoned".into()))?
            .as_ref()
            .map(|cached| cached.value.clone())
            .unwrap_or_default())
    }
}

#[async_trait]
impl ProcessService for WindowsProcessService {
    async fn terminate(
        &self,
        pid: u32,
        expected_name: &str,
    ) -> Result<ProcessOperationResult, PlatformError> {
        if pid == std::process::id() {
            return Ok(denied(
                pid,
                expected_name,
                "AIGuard cannot terminate itself",
            ));
        }
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);
        let process = system
            .process(Pid::from_u32(pid))
            .ok_or_else(|| PlatformError::Collection(format!("process {pid} no longer exists")))?;
        let actual_name = process.name().to_string_lossy().into_owned();
        if !actual_name.eq_ignore_ascii_case(expected_name) {
            return Ok(denied(
                pid,
                &actual_name,
                "process identity changed; refresh before retrying",
            ));
        }
        if let Some(reason) = protection_reason(pid, &actual_name) {
            return Ok(denied(pid, &actual_name, reason));
        }
        let success = process.kill();
        Ok(ProcessOperationResult {
            success,
            pid,
            process_name: actual_name,
            message: if success {
                "termination request sent".into()
            } else {
                "termination failed or permission was denied".into()
            },
        })
    }
}

fn process_snapshot(process: &sysinfo::Process) -> ProcessSnapshot {
    let name = process.name().to_string_lossy().into_owned();
    let reason = protection_reason(process.pid().as_u32(), &name);
    ProcessSnapshot {
        pid: process.pid().as_u32(),
        parent_pid: process.parent().map(Pid::as_u32),
        name,
        path: process
            .exe()
            .map(|path| path.to_string_lossy().into_owned()),
        command_line: if process.cmd().is_empty() {
            None
        } else {
            Some(
                process
                    .cmd()
                    .iter()
                    .map(|part| part.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        },
        cpu_usage: process.cpu_usage(),
        memory: process.memory(),
        protected: reason.is_some(),
        protection_reason: reason.map(str::to_string),
    }
}

fn denied(pid: u32, process_name: &str, reason: &str) -> ProcessOperationResult {
    ProcessOperationResult {
        success: false,
        pid,
        process_name: process_name.into(),
        message: reason.into(),
    }
}

fn protection_reason(pid: u32, name: &str) -> Option<&'static str> {
    if pid <= 4 {
        return Some("Windows kernel process is protected");
    }
    let normalized = name.trim_end_matches(".exe").to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "system"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "winlogon"
            | "svchost"
    ) {
        return Some("Windows system process is protected");
    }
    if normalized == "aiguard-desktop" || normalized == "aiguard" {
        return Some("AIGuard process is protected");
    }
    None
}

fn collect_ports() -> Vec<PortSnapshot> {
    let address_families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let Ok(sockets) = get_sockets_info(address_families, protocols) else {
        return Vec::new();
    };
    sockets
        .into_iter()
        .map(|socket| match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => PortSnapshot {
                protocol: "tcp".into(),
                address: tcp.local_addr.to_string(),
                port: tcp.local_port,
                pid: socket.associated_pids.first().copied(),
                process_name: None,
                listening: tcp.state == TcpState::Listen,
            },
            ProtocolSocketInfo::Udp(udp) => PortSnapshot {
                protocol: "udp".into(),
                address: udp.local_addr.to_string(),
                port: udp.local_port,
                pid: socket.associated_pids.first().copied(),
                process_name: None,
                listening: true,
            },
        })
        .filter(|port| port.listening)
        .collect()
}

fn attach_port_process_names(ports: &mut [PortSnapshot], processes: &[ProcessSnapshot]) {
    for port in ports {
        if port.process_name.is_some() {
            continue;
        }
        let Some(pid) = port.pid else {
            continue;
        };
        if let Some(process) = processes.iter().find(|process| process.pid == pid) {
            port.process_name = Some(process.name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protects_windows_system_processes() {
        assert!(protection_reason(4, "System").is_some());
        assert!(protection_reason(400, "lsass.exe").is_some());
        assert!(protection_reason(800, "svchost.exe").is_some());
    }

    #[test]
    fn allows_normal_user_processes() {
        assert!(protection_reason(12000, "node.exe").is_none());
        assert!(protection_reason(12001, "code.exe").is_none());
    }
}
