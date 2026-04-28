use crate::security;
use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
    process::{Command, ExitCode},
};
mod clone;

const CHILD_STACK_SIZE: usize = 1024 * 1024;

struct ExecConfig {
    root: File,
    cmd: String,
    cmd_args: Vec<String>,
}

pub fn run<'a>(mut args: impl Iterator<Item = &'a String>) -> Result<ExitCode, Box<dyn Error>> {
    let Some(id) = args.next() else {
        return Err("id argument is required".into());
    };
    let Some(cmd) = args.next() else {
        return Err("cmd argument is required".into());
    };

    let cgroup_procs = Path::new("/sys/fs/cgroup").join(id).join("cgroup.procs");
    let data =
        fs::read_to_string(&cgroup_procs).map_err(|_| format!("container {id:?} not found"))?;
    let Some(pid) = data.split_whitespace().next() else {
        return Err(format!("container {id:?} has no processes").into());
    };
    let proc_path = Path::new("/proc").join(pid);
    let root = File::open(proc_path.join("root"))?;
    let user = File::open(proc_path.join("ns/user"))?;
    let mnt = File::open(proc_path.join("ns/mnt"))?;
    let uts = File::open(proc_path.join("ns/uts"))?;
    let ipc = File::open(proc_path.join("ns/ipc"))?;
    let net = File::open(proc_path.join("ns/net"))?;
    let pid = File::open(proc_path.join("ns/pid"))?;

    setns(&user, libc::CLONE_NEWUSER)?;
    setns(&mnt, libc::CLONE_NEWNS)?;
    setns(&uts, libc::CLONE_NEWUTS)?;
    setns(&ipc, libc::CLONE_NEWIPC)?;
    setns(&net, libc::CLONE_NEWNET)?;
    setns(&pid, libc::CLONE_NEWPID)?;

    let mut stack = vec![0_u8; CHILD_STACK_SIZE];
    let pid = clone::isolate(
        exec_command,
        &mut stack,
        ExecConfig {
            root,
            cmd: cmd.clone(),
            cmd_args: args.cloned().collect(),
        },
    )?;

    // wait exited
    let mut status = 0;
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err.into());
        }
    }
    if libc::WIFEXITED(status) {
        return Ok(ExitCode::from(libc::WEXITSTATUS(status) as u8));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(ExitCode::from((128 + libc::WTERMSIG(status)) as u8));
    }

    Ok(ExitCode::FAILURE)
}

fn exec_command(config: ExecConfig) -> Result<(), Box<dyn Error>> {
    let dot = CString::new(".")?;
    let slash = CString::new("/")?;

    if unsafe { libc::fchdir(config.root.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::chroot(dot.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::chdir(slash.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }

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

    security::set_privileges()?;
    security::set_seccomp()?;

    Err(Command::new(config.cmd).args(config.cmd_args).exec().into())
}

fn setns(file: &File, nstype: libc::c_int) -> io::Result<()> {
    if unsafe { libc::setns(file.as_raw_fd(), nstype) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
