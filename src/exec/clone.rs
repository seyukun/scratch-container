use nix::{sched::CloneFlags, sched::clone, sys::signal::Signal, unistd::Pid};
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
        let args = match args.take() {
            None => {
                eprintln!("clone callback was called more than once");
                return 1;
            }
            Some(args) => args,
        };
        match func(args) {
            Err(err) => {
                eprintln!("{err}");
                1
            }
            Ok(()) => 0,
        }
    });

    Ok(unsafe {
        clone(
            callback,
            stack,
            CloneFlags::empty(),
            Some(Signal::SIGCHLD as i32),
        )?
    })
}
