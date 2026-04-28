use std::{error::Error, ffi::CString, io};

use nix::{
    sys::signal::{self, Signal},
    unistd::{self, Pid},
};

pub fn pivot_root(new_root: &str, old_root: &str) -> Result<(), Box<dyn Error>> {
    let new_root = CString::new(new_root)?;
    let old_root = CString::new(old_root)?;
    if unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn kill(pid: Pid, signal: Signal) -> Result<(), Box<dyn Error>> {
    signal::kill(pid, signal)?;
    Ok(())
}

pub fn set_hostname(hostname: &str) -> Result<(), Box<dyn Error>> {
    unistd::sethostname(hostname)?;
    Ok(())
}
