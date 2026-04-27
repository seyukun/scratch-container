use std::process::ExitCode;
mod container;
mod security;
mod user_namespace;

const RUN_USAGE: &str = "run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]";
const EXEC_USAGE: &str = "exec <id> <cmd> [args...]";

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "container".to_string());

    let Some(command) = args.next() else {
        print_usage(&program);
        return ExitCode::FAILURE;
    };

    let args: Vec<String> = args.collect();

    match command.as_str() {
        "run" => {
            if args.len() < 10 {
                eprintln!("Usage: {program} {RUN_USAGE}");
                return ExitCode::FAILURE;
            }
            match container::run(args.iter()) {
                Ok(exit_code) => exit_code,
                Err(err) => {
                    eprintln!("{}", err);
                    ExitCode::FAILURE
                }
            }
        }
        "exec" => {
            if args.len() < 2 {
                eprintln!("Usage: {program} {EXEC_USAGE}");
                return ExitCode::FAILURE;
            }

            not_implemented("exec")
        }
        "-h" | "--help" | "help" => {
            print_usage(&program);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{program}: unknown command {command:?}");
            print_usage(&program);
            ExitCode::FAILURE
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} {RUN_USAGE}");
    eprintln!("  {program} {EXEC_USAGE}");
}

fn not_implemented(command: &str) -> ExitCode {
    eprintln!("{command}: not implemented yet");
    ExitCode::FAILURE
}
