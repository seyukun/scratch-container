use scopeguard::{ScopeGuard, guard};
use std::{error::Error, process::Command};

pub fn setup(
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

pub fn cleanup(arg_id: &str, host_nic: &str) -> Result<(), Box<dyn Error>> {
    let _ = ip(&["link", "del", host_nic]);
    let _ = ip(&["netns", "del", arg_id]);

    Ok(())
}

fn ip(args: &[&str]) -> Result<(), Box<dyn Error>> {
    match Command::new("ip").args(args).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => return Err(format!("[FAILED] ip {args:?}: \n{status}").into()),
        Err(err) => return Err(format!("[FAILED] ip {args:?}: \n{err}").into()),
    }
}
