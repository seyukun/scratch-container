#!/usr/bin/env python3
import argparse
import os
import pwd
import re
import shlex
import subprocess
import sys
from pathlib import Path


UNIT_PREFIX = "scratch-container"
UNIT_DIR = Path("/etc/systemd/system")
ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def default_binary() -> Path:
    root = repo_root()
    release = root / "target" / "release" / "scratch-container"
    debug_link = root / "scratch-container"
    if release.exists():
        return release
    return debug_link


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("run this command with sudo")


def validate_id(container_id: str) -> None:
    if not ID_PATTERN.fullmatch(container_id):
        raise SystemExit(
            "container id may only contain letters, numbers, '.', '_', and '-'"
        )


def unit_name(container_id: str) -> str:
    validate_id(container_id)
    return f"{UNIT_PREFIX}-{container_id}.service"


def unit_path(container_id: str) -> Path:
    return UNIT_DIR / unit_name(container_id)


def run_checked(argv: list[str]) -> None:
    subprocess.run(argv, check=True)


def shell_exec_line(argv: list[str]) -> str:
    return "exec " + shlex.join(argv)


def systemd_quote_env(name: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{name}={escaped}"'


def sudo_environment() -> list[str]:
    user = os.environ.get("SUDO_USER")
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")

    if user and uid and gid:
        return [
            systemd_quote_env("SUDO_USER", user),
            systemd_quote_env("SUDO_UID", uid),
            systemd_quote_env("SUDO_GID", gid),
        ]

    if user:
        info = pwd.getpwnam(user)
        return [
            systemd_quote_env("SUDO_USER", user),
            systemd_quote_env("SUDO_UID", str(info.pw_uid)),
            systemd_quote_env("SUDO_GID", str(info.pw_gid)),
        ]

    return []


def write_unit(args: argparse.Namespace) -> Path:
    binary = Path(args.binary).resolve()
    rootfs = Path(args.rootfs).resolve()
    validate_id(args.id)

    if not binary.exists():
        raise SystemExit(f"container binary not found: {binary}")
    if not rootfs.exists():
        raise SystemExit(f"rootfs not found: {rootfs}")

    command = [
        str(binary),
        "run",
        str(rootfs),
        args.id,
        args.hostname,
        args.ip_range,
        args.route_ip,
        args.master_br_nic,
        args.cpu_quota,
        args.cpu_period,
        args.mem_m,
        *args.command,
    ]

    path = unit_path(args.id)
    path.write_text(
        "\n".join(
            [
                "[Unit]",
                f"Description=Scratch container {args.id}",
                "After=network-online.target",
                "Wants=network-online.target",
                "",
                "[Service]",
                "Type=simple",
                "KillMode=control-group",
                "Delegate=yes",
                "Restart=no",
                "Environment=" + " ".join(sudo_environment()),
                f"WorkingDirectory={repo_root()}",
                f"ExecStart=/bin/sh -lc {shlex.quote(shell_exec_line(command))}",
                "",
                "[Install]",
                "WantedBy=multi-user.target",
                "",
            ]
        )
    )
    return path


def cmd_run(args: argparse.Namespace) -> None:
    require_root()
    if not args.command:
        raise SystemExit("run requires a container command")

    path = write_unit(args)
    run_checked(["systemctl", "daemon-reload"])
    run_checked(["systemctl", "enable", unit_name(args.id)])
    run_checked(["systemctl", "start", unit_name(args.id)])
    print(path)


def cmd_exec(args: argparse.Namespace) -> None:
    require_root()
    validate_id(args.id)
    if not args.command:
        raise SystemExit("exec requires a command")
    binary = Path(args.binary).resolve()
    if not binary.exists():
        raise SystemExit(f"container binary not found: {binary}")
    os.execv(str(binary), [str(binary), "exec", args.id, *args.command])


def cmd_start(args: argparse.Namespace) -> None:
    require_root()
    run_checked(["systemctl", "enable", unit_name(args.id)])
    run_checked(["systemctl", "start", unit_name(args.id)])


def cmd_stop(args: argparse.Namespace) -> None:
    require_root()
    run_checked(["systemctl", "stop", unit_name(args.id)])
    run_checked(["systemctl", "disable", unit_name(args.id)])


def cmd_status(args: argparse.Namespace) -> None:
    require_root()
    run_checked(["systemctl", "status", unit_name(args.id), "--no-pager"])


def cmd_rm(args: argparse.Namespace) -> None:
    require_root()
    name = unit_name(args.id)
    path = unit_path(args.id)

    subprocess.run(["systemctl", "stop", name], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "reset-failed", name], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", name], check=False, stderr=subprocess.DEVNULL)
    if path.exists():
        path.unlink()
    run_checked(["systemctl", "daemon-reload"])


def add_common_binary(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--binary",
        default=str(default_binary()),
        help="scratch-container binary path",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage scratch-container instances with systemd"
    )
    sub = parser.add_subparsers(dest="command_name", required=True)

    run_p = sub.add_parser("run", help="create a systemd unit and start a container")
    add_common_binary(run_p)
    run_p.add_argument("rootfs")
    run_p.add_argument("id")
    run_p.add_argument("hostname")
    run_p.add_argument("ip_range")
    run_p.add_argument("route_ip")
    run_p.add_argument("master_br_nic")
    run_p.add_argument("cpu_quota")
    run_p.add_argument("cpu_period")
    run_p.add_argument("mem_m")
    run_p.add_argument("command", nargs=argparse.REMAINDER)
    run_p.set_defaults(func=cmd_run)

    exec_p = sub.add_parser("exec", help="execute a command in a running container")
    add_common_binary(exec_p)
    exec_p.add_argument("id")
    exec_p.add_argument("command", nargs=argparse.REMAINDER)
    exec_p.set_defaults(func=cmd_exec)

    start_p = sub.add_parser("start", help="start an existing container unit")
    start_p.add_argument("id")
    start_p.set_defaults(func=cmd_start)

    stop_p = sub.add_parser("stop", help="stop a container unit")
    stop_p.add_argument("id")
    stop_p.set_defaults(func=cmd_stop)

    status_p = sub.add_parser("status", help="show systemd status for a container unit")
    status_p.add_argument("id")
    status_p.set_defaults(func=cmd_status)

    rm_p = sub.add_parser("rm", help="stop and remove a container unit")
    rm_p.add_argument("id")
    rm_p.set_defaults(func=cmd_rm)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as err:
        return err.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
