use nix::{sched::CloneFlags, sched::clone, sys::signal::Signal, unistd::Pid};
use std::error::Error;

pub(super) fn isolate<T>(
    func: fn(T) -> Result<(), Box<dyn Error>>,
    stack: &mut [u8],
    args: T,
) -> Result<Pid, Box<dyn Error>> {
    let mut args = Some(args);
    let callback = Box::new(move || {
        let args = match args.take() {
            Some(args) => args,
            None => {
                eprintln!("clone callback was called more than once");
                return 1;
            }
        };

        match func(args) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("{err}");
                1
            }
        }
    });

    Ok(unsafe {
        clone(
            callback,
            stack,
            CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWNET,
            Some(Signal::SIGCHLD as i32),
        )?
    })
}
