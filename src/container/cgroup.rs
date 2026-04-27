use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

pub fn setup(
    id: &str,
    pid: libc::pid_t,
    cpu_quota: &str,
    cpu_period: &str,
    mem_limit: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let cgroup = Path::new("/sys/fs/cgroup").join(id);
    fs::create_dir_all(&cgroup)?;

    fs::write(cgroup.join("pids.max"), "64")?;
    fs::write(cgroup.join("cgroup.procs"), pid.to_string())?;
    fs::write(cgroup.join("cpu.max"), format!("{cpu_quota} {cpu_period}"))?;
    fs::write(cgroup.join("memory.max"), mem_limit)?;

    Ok(cgroup)
}

pub fn cleanup(cgroup: &Path) -> Result<(), Box<dyn Error>> {
    fs::remove_dir(cgroup)?;

    Ok(())
}
