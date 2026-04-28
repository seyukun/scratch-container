use nix::{
    fcntl::AT_FDCWD,
    mount::{MntFlags, MsFlags, mount, umount2},
    sys::{
        signal::{self, Signal},
        stat::{self, FchmodatFlags, Mode},
        wait,
    },
    unistd,
};
use scopeguard::defer;
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
    iterator::Signals,
};
use std::{
    error::Error,
    fs,
    io::{self, Read as _},
    os::{
        fd::{self, AsRawFd as _, FromRawFd as _},
        unix::process::CommandExt as _,
    },
    path::Path,
    process::{Command, ExitCode},
    thread,
};
mod cgroup;
mod clone;
mod id_map;
mod network;
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
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!("failed to stat network namespace {arg_id:?}: {err}").into());
        }
    }

    // pipe
    let (rfd, wfd) = unistd::pipe()?;

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
            match signal::kill(pid, sig) {
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
    let (mut rfd, wfd) = unsafe {
        (
            io::PipeReader::try_from(fd::OwnedFd::from_raw_fd(config.pipefd.0))?,
            io::PipeWriter::try_from(fd::OwnedFd::from_raw_fd(config.pipefd.1))?,
        )
    };
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
    let rootfs = Path::new(&config.rootfs);
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )?;
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;
    for dir in ["proc", "sys", "dev", "run", "tmp", "oldroot"] {
        unistd::mkdir(&rootfs.join(dir), Mode::from_bits_truncate(0o755))?;
    }
    unistd::pivot_root(rootfs, &rootfs.join("oldroot"))?;

    // mount proc/sysfs/devtmpfs and bind mount some proc/sys entries
    unistd::chdir("/")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )?;
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
        let metadata = match fs::metadata(target) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            mount(
                Some("tmpfs"),
                target,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("mode=755"),
            )?;
        } else {
            mount(
                Some("/oldroot/dev/null"),
                target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            )?;
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
        match fs::metadata(target) {
            Ok(_) => {}
            Err(_) => continue,
        }
        mount(
            Some(target),
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;
        mount(
            Some(target),
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
            None::<&str>,
        )?;
    }

    // setup dev
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=755"),
    )?;
    unistd::mkdir("/dev/pts", Mode::from_bits_truncate(0o755))?;
    unistd::mkdir("/dev/shm", Mode::from_bits_truncate(0o755))?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::empty(),
        Some("newinstance,ptmxmode=666,mode=620,gid=0"),
    )?;
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=64m"),
    )?;
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=755"),
    )?;

    stat::fchmodat(
        AT_FDCWD,
        "/tmp",
        Mode::from_bits_truncate(0o1777),
        FchmodatFlags::FollowSymlink,
    )?;

    for dev in ["null", "zero", "full", "random", "urandom", "tty"] {
        let target = Path::new("/dev").join(dev);
        let source = Path::new("/oldroot/dev").join(dev);
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&target)?;
        mount(
            Some(&source),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )?;
    }
    unistd::symlinkat("pts/ptmx", AT_FDCWD, "/dev/ptmx")?;

    umount2("/oldroot", MntFlags::MNT_DETACH)?;
    unistd::unlinkat(AT_FDCWD, "/oldroot", unistd::UnlinkatFlags::RemoveDir)?;

    unistd::sethostname(&config.hostname)?;
    security::set_privileges()?;
    security::set_seccomp()?;

    Err(Command::new(&config.cmd)
        .args(&config.cmd_args)
        .exec()
        .into())
}
