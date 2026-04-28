use crate::security;
use nix::{sched::*, sys::wait, unistd};
use std::{
    error::Error,
    fs::{self, File},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, ExitCode},
};
mod clone;

const CHILD_STACK_SIZE: usize = 1024 * 1024;

struct ExecConfig {
    root: File,
    cmd: String,
    args: Vec<String>,
}

pub fn run<'a>(mut args: impl Iterator<Item = &'a String>) -> Result<ExitCode, Box<dyn Error>> {
    let Some(id) = args.next() else {
        return Err("id argument is required".into());
    };
    let Some(cmd) = args.next() else {
        return Err("cmd argument is required".into());
    };

    let cgroup_procs_path = Path::new("/sys/fs/cgroup").join(id).join("cgroup.procs");
    let cgroup_procs = match fs::read_to_string(&cgroup_procs_path) {
        Ok(data) => data,
        Err(_) => return Err(format!("container {id:?} not found").into()),
    };
    let pid = match cgroup_procs.split_whitespace().next() {
        Some(pid) => pid.to_string(),
        None => return Err(format!("container {id:?} has no processes").into()),
    };
    let proc_path = Path::new("/proc").join(pid);
    let root = File::open(proc_path.join("root"))?;
    let user = File::open(proc_path.join("ns/user"))?;
    let mnt = File::open(proc_path.join("ns/mnt"))?;
    let uts = File::open(proc_path.join("ns/uts"))?;
    let ipc = File::open(proc_path.join("ns/ipc"))?;
    let net = File::open(proc_path.join("ns/net"))?;
    let pid = File::open(proc_path.join("ns/pid"))?;

    setns(&user, CloneFlags::CLONE_NEWUSER)?;
    setns(&mnt, CloneFlags::CLONE_NEWNS)?;
    setns(&uts, CloneFlags::CLONE_NEWUTS)?;
    setns(&ipc, CloneFlags::CLONE_NEWIPC)?;
    setns(&net, CloneFlags::CLONE_NEWNET)?;
    setns(&pid, CloneFlags::CLONE_NEWPID)?;

    let mut stack = vec![0_u8; CHILD_STACK_SIZE];
    let pid = clone::isolate(
        exec_command,
        &mut stack,
        ExecConfig {
            root,
            cmd: cmd.clone(),
            args: args.cloned().collect(),
        },
    )?;

    match wait::waitpid(pid, None)? {
        wait::WaitStatus::Exited(_, status) => Ok(ExitCode::from(status as u8)),
        wait::WaitStatus::Signaled(_, signal, _) => Ok(ExitCode::from((128 + signal as i32) as u8)),
        _ => Ok(ExitCode::FAILURE),
    }
}

fn exec_command(config: ExecConfig) -> Result<(), Box<dyn Error>> {
    unistd::fchdir(&config.root)?;
    unistd::chroot(".")?;
    unistd::chdir("/")?;

    let root_gid = unistd::Gid::from_raw(0);
    let root_uid = unistd::Uid::from_raw(0);

    unistd::setgroups(&[root_gid])?;
    unistd::setgid(root_gid)?;
    unistd::setuid(root_uid)?;

    security::set_privileges()?;
    security::set_seccomp()?;

    Err(Command::new(config.cmd).args(config.args).exec().into())
}
