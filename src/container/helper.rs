use std::{error::Error, ffi::CString, io};

pub fn pivot_root(new_root: &str, old_root: &str) -> Result<(), Box<dyn Error>> {
    let new_root = CString::new(new_root)?;
    let old_root = CString::new(old_root)?;
    if unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn kill(pid: libc::pid_t, signal: i32) -> Result<(), Box<dyn Error>> {
    if unsafe { libc::kill(pid, signal.into()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn set_hostname(hostname: &str) -> Result<(), Box<dyn Error>> {
    if unsafe { libc::sethostname(hostname.as_ptr().cast::<libc::c_char>(), hostname.len()) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
