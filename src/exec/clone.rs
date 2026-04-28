use std::{error::Error, io};

struct RustFuncSet<T> {
    func: fn(T) -> Result<(), Box<dyn Error>>,
    args: T,
}

pub fn isolate<T>(
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
            libc::SIGCHLD,
            child_args.cast(),
        )
    };

    if pid < 0 {
        unsafe {
            drop(Box::from_raw(child_args));
        }
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
