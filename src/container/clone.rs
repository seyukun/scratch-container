use std::{error::Error, io};

struct RustFuncSet<T> {
    func: fn(T) -> Result<(), Box<dyn Error>>,
    args: T,
}

pub(super) fn isolate<T>(
    func: fn(T) -> Result<(), Box<dyn Error>>,
    stack: &mut [u8],
    args: T,
) -> Result<libc::pid_t, Box<dyn Error>>
where
    T: 'static,
{
    let child_args = Box::into_raw(Box::new(RustFuncSet { func, args }));

    let pid = unsafe {
        libc::clone(
            entry::<T>,
            stack.as_mut_ptr().add(stack.len()).cast(),
            flags(),
            child_args.cast(),
        )
    };

    unsafe {
        drop(Box::from_raw(child_args));
    }

    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(pid)
}

extern "C" fn entry<T>(arg: *mut libc::c_void) -> libc::c_int {
    let child_args = unsafe { Box::from_raw(arg.cast::<RustFuncSet<T>>()) };

    if let Err(err) = (child_args.func)(child_args.args) {
        eprintln!("{err}");
        return 1;
    }

    0
}

fn flags() -> libc::c_int {
    libc::SIGCHLD
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWNET
}
