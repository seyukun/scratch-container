use nix::{sched::CloneFlags, sys::signal::Signal, unistd::Pid};
use std::error::Error;

pub fn isolate<T>(
    func: fn(T) -> Result<(), Box<dyn Error>>,
    stack: &mut [u8],
    args: T,
) -> Result<Pid, Box<dyn Error>>
where
    T: 'static,
{
    let mut args = Some(args);
    let callback = Box::new(move || {
        let Some(args) = args.take() else {
            eprintln!("clone callback was called more than once");
            return 1;
        };

        if let Err(err) = func(args) {
            eprintln!("{err}");
            return 1;
        }

        0
    });

    let pid = unsafe {
        nix::sched::clone(
            callback,
            stack,
            CloneFlags::empty(),
            Some(Signal::SIGCHLD as i32),
        )?
    };
    Ok(pid)
}
