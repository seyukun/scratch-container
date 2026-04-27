use std::io;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const AUDIT_ARCH_X86_64: u32 = 62 | 0x80000000 | 0x40000000;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const CAP_CHOWN: i32 = 0;
const CAP_DAC_OVERRIDE: i32 = 1;
const CAP_DAC_READ_SEARCH: i32 = 2;
const CAP_FOWNER: i32 = 3;
const CAP_FSETID: i32 = 4;
const CAP_KILL: i32 = 5;
const CAP_SETGID: i32 = 6;
const CAP_SETUID: i32 = 7;
const CAP_SETPCAP: i32 = 8;
const CAP_LINUX_IMMUTABLE: i32 = 9;
const CAP_NET_BIND_SERVICE: i32 = 10;
const CAP_NET_BROADCAST: i32 = 11;
const CAP_NET_ADMIN: i32 = 12;
const CAP_NET_RAW: i32 = 13;
const CAP_IPC_LOCK: i32 = 14;
const CAP_IPC_OWNER: i32 = 15;
const CAP_SYS_MODULE: i32 = 16;
const CAP_SYS_RAWIO: i32 = 17;
const CAP_SYS_CHROOT: i32 = 18;
const CAP_SYS_PTRACE: i32 = 19;
const CAP_SYS_PACCT: i32 = 20;
const CAP_SYS_ADMIN: i32 = 21;
const CAP_SYS_BOOT: i32 = 22;
const CAP_SYS_NICE: i32 = 23;
const CAP_SYS_RESOURCE: i32 = 24;
const CAP_SYS_TIME: i32 = 25;
const CAP_SYS_TTY_CONFIG: i32 = 26;
const CAP_MKNOD: i32 = 27;
const CAP_LEASE: i32 = 28;
const CAP_AUDIT_WRITE: i32 = 29;
const CAP_AUDIT_CONTROL: i32 = 30;
const CAP_SETFCAP: i32 = 31;
const CAP_MAC_OVERRIDE: i32 = 32;
const CAP_MAC_ADMIN: i32 = 33;
const CAP_SYSLOG: i32 = 34;
const CAP_WAKE_ALARM: i32 = 35;
const CAP_BLOCK_SUSPEND: i32 = 36;
const CAP_AUDIT_READ: i32 = 37;
const CAP_PERFMON: i32 = 38;
const CAP_BPF: i32 = 39;
const CAP_CHECKPOINT_RESTORE: i32 = 40;
const CAP_LAST_CAP: i32 = 40;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn set_privileges() -> io::Result<()> {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)?;
    clear_all_inheritable_caps()?;
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)?;

    let keep_caps = [
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_FOWNER,
        CAP_FSETID,
        CAP_KILL,
        CAP_SETGID,
        CAP_SETUID,
        CAP_NET_BIND_SERVICE,
        CAP_NET_RAW,
        CAP_SYS_CHROOT,
        CAP_AUDIT_WRITE,
        CAP_SETFCAP,
    ];
    for cap in 0..=CAP_LAST_CAP {
        if keep_caps.contains(&cap) {
            continue;
        }
        prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0)?;
    }

    Ok(())
}

pub fn set_seccomp() -> io::Result<()> {
    let deny = [
        libc::SYS_acct,
        libc::SYS_add_key,
        libc::SYS_bpf,
        libc::SYS_clock_adjtime,
        libc::SYS_clock_settime,
        libc::SYS_delete_module,
        libc::SYS_finit_module,
        177, // get_kernel_syms
        libc::SYS_get_mempolicy,
        libc::SYS_init_module,
        libc::SYS_ioperm,
        libc::SYS_iopl,
        426, // io_uring_enter
        427, // io_uring_register
        425, // io_uring_setup
        libc::SYS_kcmp,
        320, // kexec_file_load
        libc::SYS_kexec_load,
        libc::SYS_keyctl,
        212, // lookup_dcookie
        libc::SYS_mbind,
        libc::SYS_mount,
        libc::SYS_move_pages,
        180, // nfsservctl
        libc::SYS_open_by_handle_at,
        libc::SYS_perf_event_open,
        libc::SYS_personality,
        libc::SYS_pivot_root,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_ptrace,
        178, // query_module
        libc::SYS_quotactl,
        libc::SYS_reboot,
        libc::SYS_request_key,
        libc::SYS_set_mempolicy,
        libc::SYS_setns,
        libc::SYS_settimeofday,
        201, // time
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_sysfs,
        156, // ni_syscall
        166, // umount
        libc::SYS_unshare,
        libc::SYS_userfaultfd,
        libc::SYS_ustat,
    ];

    let mut filter = vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone as u32, 0, 3),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16),
        bpf_jump(
            BPF_JMP | BPF_JSET | BPF_K,
            (libc::CLONE_NEWNS
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWCGROUP) as u32,
            0,
            1,
        ),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ];

    for nr in deny {
        filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        filter.push(bpf_stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }

    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };

    prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        &prog as *const libc::sock_fprog as libc::c_ulong,
        0,
        0,
    )
}

fn clear_all_inheritable_caps() -> io::Result<()> {
    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];

    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    data[0].inheritable = 0;
    data[1].inheritable = 0;

    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn prctl(
    option: libc::c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> io::Result<()> {
    if unsafe { libc::prctl(option, arg2, arg3, arg4, arg5) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
