use nix::{
    sys::{signal::Signal, wait},
    unistd,
};
use scopeguard::defer;
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
    iterator::Signals,
};
use std::{
    env,
    error::Error,
    fs,
    io::{self, ErrorKind, PipeReader, Read},
    os::{
        fd::{self, AsRawFd, FromRawFd},
        unix::{self, fs::PermissionsExt, process::CommandExt},
    },
    path::Path,
    process::{Command, ExitCode},
    thread,
};
use sys_mount::{Mount, MountFlags, UnmountFlags, unmount};
mod cgroup;
mod clone;
mod id_map;
mod network;
use super::helper;
use super::security;

const CHILD_STACK_SIZE: usize = 1024 * 1024;

struct ChildConfig {
    rootfs: String,
    hostname: String,
    cmd: String,
    cmd_args: Vec<String>,
    pipefd: (fd::RawFd, fd::RawFd),
}

pub fn run<'a>(mut args: impl Iterator<Item = &'a String>) -> Result<ExitCode, Box<dyn Error>> {
    let Some(arg_rootfs) = args.next() else {
        return Err("rootfs argument is required".into());
    };
    let Some(arg_id) = args.next() else {
        return Err("id argument is required".into());
    };
    let Some(arg_hostname) = args.next() else {
        return Err("hostname argument is required".into());
    };
    let Some(arg_ip_range) = args.next() else {
        return Err("ip/range argument is required".into());
    };
    let Some(arg_route_ip) = args.next() else {
        return Err("route-ip argument is required".into());
    };
    let Some(arg_master_br_nic) = args.next() else {
        return Err("master-br-nic argument is required".into());
    };
    let Some(arg_cpu_quota) = args.next() else {
        return Err("cpu-quota argument is required".into());
    };
    let Some(arg_cpu_period) = args.next() else {
        return Err("cpu-period argument is required".into());
    };
    let Some(arg_mem_limit) = args.next() else {
        return Err("mem-M argument is required".into());
    };
    let Some(arg_cmd) = args.next() else {
        return Err("cmd argument is required".into());
    };
    let cmd_args: Vec<String> = args.cloned().collect();

    let netns_path = Path::new("/var/run/netns").join(arg_id);
    match fs::metadata(&netns_path) {
        Ok(_) => {
            return Err(format!("network namespace {arg_id:?} already exists").into());
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!("failed to stat network namespace {arg_id:?}: {err}").into());
        }
    }

    // pipe
    let (rfd, wfd) = io::pipe()?;

    // clone and isolate
    let mut stack = vec![0_u8; CHILD_STACK_SIZE];
    let pid = clone::isolate(
        child,
        &mut stack,
        ChildConfig {
            rootfs: arg_rootfs.clone(),
            hostname: arg_hostname.clone(),
            cmd: arg_cmd.clone(),
            cmd_args,
            pipefd: (rfd.as_raw_fd(), wfd.as_raw_fd()),
        },
    )?;

    id_map::apply(pid)?;

    drop(rfd);

    // signal handler
    let mut signals = Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM])?;
    let signals_handle = signals.handle();
    let signal_thread = thread::spawn(move || {
        for sig in signals.forever() {
            let sig = match Signal::try_from(sig) {
                Ok(signal) => signal,
                Err(_) => {
                    eprintln!("received invalid signal: {}", sig);
                    continue;
                }
            };
            match helper::kill(pid, sig) {
                Ok(()) => {}
                Err(err) => eprintln!("failed to forward signal {} to container: {err}", sig),
            }
        }
    });
    defer! {
        signals_handle.close();
        let _ = signal_thread.join();
    }

    // network
    let host_nic = format!("veth-{pid}");
    let ctr_nic = format!("ct-{pid}");
    network::setup(
        arg_id,
        arg_ip_range,
        arg_route_ip,
        arg_master_br_nic,
        &pid.to_string(),
        &host_nic,
        &ctr_nic,
    )?;
    defer!(if let Err(err) = network::cleanup(arg_id, &host_nic) {
        eprintln!("failed to cleanup network: {err}");
    });

    // cgroup
    let cgroup = cgroup::setup(arg_id, pid, arg_cpu_quota, arg_cpu_period, arg_mem_limit)?;
    defer!(if let Err(err) = cgroup::cleanup(&cgroup) {
        eprintln!("failed to cleanup {}: {err}", cgroup.display());
    });

    // goback
    drop(wfd);

    // wait exited
    match wait::waitpid(pid, None)? {
        wait::WaitStatus::Exited(_, status) => Ok(ExitCode::from(status as u8)),
        wait::WaitStatus::Signaled(_, signal, _) => Ok(ExitCode::from((128 + signal as i32) as u8)),
        _ => Ok(ExitCode::FAILURE),
    }
}

fn child(config: ChildConfig) -> Result<(), Box<dyn Error>> {
    let rfd = unsafe { fd::OwnedFd::from_raw_fd(config.pipefd.0) };
    let wfd = unsafe { fd::OwnedFd::from_raw_fd(config.pipefd.1) };
    let mut rfd = PipeReader::try_from(rfd)?;
    drop(wfd);

    // goto -> setup-child-process -> comeback
    let mut buf = Vec::new();
    rfd.read_to_end(&mut buf)?;
    drop(rfd);

    // set uid/gid
    let root_gid = unistd::Gid::from_raw(0);
    let root_uid = unistd::Uid::from_raw(0);
    unistd::setgroups(&[root_gid])?;
    unistd::setgid(root_gid)?;
    unistd::setuid(root_uid)?;

    // mount pivot_root
    Mount::builder()
        .flags(MountFlags::from_bits_retain(
            libc::MS_PRIVATE | libc::MS_REC,
        ))
        .mount("", "/")?;
    Mount::builder()
        .flags(MountFlags::BIND | MountFlags::REC)
        .mount(&config.rootfs, &config.rootfs)?;
    for dir in ["proc", "sys", "dev", "run", "tmp", "oldroot"] {
        fs::create_dir_all(Path::new(&config.rootfs).join(dir))?;
    }
    let oldroot = Path::new(&config.rootfs)
        .join("oldroot")
        .to_str()
        .ok_or("failed to convert oldroot path to string")?
        .to_string();
    helper::pivot_root(&config.rootfs, &oldroot)?;

    // mount proc/sysfs/devtmpfs and bind mount some proc/sys entries
    env::set_current_dir("/")?;
    Mount::builder().fstype("proc").mount("proc", "/proc")?;
    Mount::builder()
        .fstype("sysfs")
        .flags(MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC)
        .mount("sysfs", "/sys")?;
    for target in [
        "/proc/acpi",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sysrq-trigger",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
        "/sys/fs/cgroup",
        "/sys/kernel/config",
        "/sys/kernel/debug",
        "/sys/kernel/security",
        "/sys/kernel/tracing",
        "/sys/module",
        "/sys/power",
    ] {
        let Ok(info) = fs::metadata(target) else {
            continue;
        };
        if info.is_dir() {
            let flag =
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
            Mount::builder()
                .fstype("tmpfs")
                .flags(flag)
                .data("mode=755")
                .mount("tmpfs", target)?;
        } else {
            let flag = MountFlags::BIND | MountFlags::RDONLY;
            Mount::builder()
                .flags(flag)
                .mount("/oldroot/dev/null", target)?;
        }
    }
    for target in [
        "/proc/asound",
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysvipc",
    ] {
        let Ok(_) = fs::metadata(target) else {
            continue;
        };
        let flag = MountFlags::BIND | MountFlags::REC;
        Mount::builder().flags(flag).mount(target, target)?;
        let flag = MountFlags::BIND | MountFlags::REMOUNT | MountFlags::RDONLY | MountFlags::REC;
        Mount::builder().flags(flag).mount(target, target)?;
    }

    // setup dev
    Mount::builder()
        .fstype("tmpfs")
        .flags(MountFlags::NOSUID)
        .data("mode=755")
        .mount("tmpfs", "/dev")?;
    fs::create_dir_all("/dev/pts")?;
    fs::create_dir_all("/dev/shm")?;
    Mount::builder()
        .fstype("devpts")
        .data("newinstance,ptmxmode=666,mode=620,gid=0")
        .mount("devpts", "/dev/pts")?;
    Mount::builder()
        .fstype("tmpfs")
        .flags(MountFlags::NOSUID | MountFlags::NODEV)
        .data("mode=1777,size=64m")
        .mount("tmpfs", "/dev/shm")?;
    Mount::builder()
        .fstype("tmpfs")
        .flags(MountFlags::NOSUID | MountFlags::NODEV)
        .data("mode=755")
        .mount("tmpfs", "/run")?;

    fs::set_permissions("/tmp", fs::Permissions::from_mode(0o1777))?;

    for dev in ["null", "zero", "full", "random", "urandom", "tty"] {
        let target = Path::new("/dev").join(dev);
        let source = Path::new("/oldroot/dev").join(dev);

        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&target)?;
        Mount::builder()
            .flags(MountFlags::BIND)
            .mount(source, target)?;
    }
    unix::fs::symlink("pts/ptmx", "/dev/ptmx")?;

    unmount("/oldroot", UnmountFlags::DETACH)?;
    fs::remove_dir("/oldroot")?;

    helper::set_hostname(&config.hostname)?;
    security::set_privileges()?;
    security::set_seccomp()?;

    Err(Command::new(&config.cmd)
        .args(&config.cmd_args)
        .exec()
        .into())
}
