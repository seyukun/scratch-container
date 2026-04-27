use crate::{security, user_namespace};
use scopeguard::{ScopeGuard, defer, guard};
use std::{
    env,
    error::Error,
    ffi::CString,
    fs,
    io::{self, ErrorKind, PipeReader, Read},
    os::{
        fd::{self, AsRawFd, FromRawFd},
        unix::{self, fs::PermissionsExt, process::CommandExt},
    },
    path::Path,
    process::{Command, ExitCode},
};
use sys_mount::{Mount, MountFlags, UnmountFlags, unmount};

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
    let pipefd = io::pipe()?;
    let (rfd, wfd) = pipefd;

    // clone
    let mut stack = vec![0_u8; CHILD_STACK_SIZE];
    let config = Box::new(ChildConfig {
        rootfs: arg_rootfs.clone(),
        hostname: arg_hostname.clone(),
        cmd: arg_cmd.clone(),
        cmd_args,
        pipefd: (rfd.as_raw_fd(), wfd.as_raw_fd()),
    });
    let pid = unsafe {
        libc::clone(
            child_run_c,
            stack.as_mut_ptr().add(stack.len()).cast(),
            libc::SIGCHLD
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUSER
                | libc::CLONE_NEWNET,
            Box::into_raw(config).cast(),
        )
    };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }

    drop(rfd);

    // user namespace
    let (uid_mappings, gid_mappings) = user_namespace::mappings()?;
    let uid_map = uid_mappings
        .iter()
        .map(|map| format!("{} {} {}\n", map.container_id, map.host_id, map.size))
        .collect::<String>();
    let gid_map = gid_mappings
        .iter()
        .map(|map| format!("{} {} {}\n", map.container_id, map.host_id, map.size))
        .collect::<String>();
    fs::write(format!("/proc/{pid}/setgroups"), "allow")?;
    fs::write(format!("/proc/{pid}/uid_map"), uid_map)?;
    fs::write(format!("/proc/{pid}/gid_map"), gid_map)?;

    // network
    let host_nic = format!("veth-{pid}");
    setup_network(
        arg_id,
        arg_ip_range,
        arg_route_ip,
        arg_master_br_nic,
        &pid.to_string(),
        &host_nic,
        &format!("ct-{pid}"),
    )?;
    defer!(if let Err(err) = cleanup_network(arg_id, &host_nic) {
        eprintln!("failed to cleanup network: {err}");
    });

    // cgroup
    let cgroup = Path::new("/sys/fs/cgroup").join(arg_id);
    fs::create_dir_all(&cgroup)?;
    defer!(if let Err(err) = fs::remove_dir(&cgroup) {
        let content = fs::read_to_string(&cgroup)
            .unwrap_or_else(|_| "<failed to read cgroup content>".to_string());
        eprintln!(
            "failed to cleanup cgroup: {err} ({} > remaining processes: {content})",
            cgroup.display()
        );
    });
    let pids_max = "64";
    let cgroup_pids = pid.to_string();
    let cpu_max = format!("{arg_cpu_quota} {arg_cpu_period}");
    fs::write(cgroup.join("pids.max"), pids_max)?;
    fs::write(cgroup.join("cgroup.procs"), cgroup_pids)?;
    fs::write(cgroup.join("cpu.max"), cpu_max)?;
    fs::write(cgroup.join("memory.max"), arg_mem_limit)?;

    // goback
    drop(wfd);

    // wait exited
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(ExitCode::SUCCESS)
}

extern "C" fn child_run_c(arg: *mut libc::c_void) -> libc::c_int {
    let config = unsafe { Box::from_raw(arg.cast::<ChildConfig>()) };

    if let Err(err) = child_run(*config) {
        eprintln!("{err}");
        return 1;
    }

    0
}

fn child_run(config: ChildConfig) -> Result<(), Box<dyn Error>> {
    let rfd = unsafe { fd::OwnedFd::from_raw_fd(config.pipefd.0) };
    let wfd = unsafe { fd::OwnedFd::from_raw_fd(config.pipefd.1) };
    let mut rfd = PipeReader::try_from(rfd)?;
    drop(wfd);

    // goto -> setup-child-process -> comeback
    let mut buf = Vec::new();
    rfd.read_to_end(&mut buf)?;
    drop(rfd);

    // set uid/gid
    let groups = [0 as libc::gid_t];
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::setgid(0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::setuid(0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }

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
    let c_rootfs = CString::new(config.rootfs.as_str())?;
    let c_oldroot = CString::new(oldroot.as_str())?;
    let result =
        unsafe { libc::syscall(libc::SYS_pivot_root, c_rootfs.as_ptr(), c_oldroot.as_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }

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

    if unsafe {
        libc::sethostname(
            config.hostname.as_ptr().cast::<libc::c_char>(),
            config.hostname.len(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }

    security::set_privileges()?;
    security::set_seccomp()?;

    Err(Command::new(&config.cmd)
        .args(&config.cmd_args)
        .exec()
        .into())
}

fn setup_network(
    id: &str,
    ip_range: &str,
    route: &str,
    mstr_br_nic: &str,
    ctr_pid: &str,
    hst_nic: &str,
    ctr_nic: &str,
) -> Result<(), Box<dyn Error>> {
    ip(&["netns", "attach", id, ctr_pid])?;
    let cleanup_netns = guard(id, |id| {
        let _ = ip(&["netns", "del", id]);
    });

    ip(&[
        "link", "add", hst_nic, "type", "veth", "peer", "name", ctr_nic,
    ])?;
    let cleanup_host_nic = guard(hst_nic, |nic| {
        let _ = ip(&["link", "del", nic]);
    });

    ip(&["link", "set", ctr_nic, "netns", id])?;
    ip(&["link", "set", hst_nic, "master", mstr_br_nic])?;
    ip(&["link", "set", hst_nic, "up"])?;
    ip(&[
        "netns", "exec", id, "ip", "link", "set", ctr_nic, "name", "eth0",
    ])?;
    ip(&[
        "netns", "exec", id, "ip", "addr", "add", ip_range, "dev", "eth0",
    ])?;
    ip(&["netns", "exec", id, "ip", "link", "set", "lo", "up"])?;
    ip(&["netns", "exec", id, "ip", "link", "set", "eth0", "up"])?;
    ip(&[
        "netns", "exec", id, "ip", "route", "add", "default", "via", route,
    ])?;

    ScopeGuard::into_inner(cleanup_netns);
    ScopeGuard::into_inner(cleanup_host_nic);

    Ok(())
}

fn cleanup_network(arg_id: &str, host_nic: &str) -> Result<(), Box<dyn Error>> {
    let _ = ip(&["link", "del", host_nic]);
    let _ = ip(&["netns", "del", arg_id]);

    Ok(())
}

fn ip(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(format!("[FAILED] ip {args:?}: \n{status}").into());
    }

    Ok(())
}
