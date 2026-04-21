//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

const (
	prSetSeccomp = 22

	seccompModeFilter = 2

	SECCOMP_MODE_DISABLED = 0 /* seccomp is not in use. */
	SECCOMP_MODE_STRICT   = 1 /* uses hard-coded filter. */
	SECCOMP_MODE_FILTER   = 2 /* uses user-supplied filter. */

	/* Valid operations for seccomp syscall. */
	SECCOMP_SET_MODE_STRICT  = 0
	SECCOMP_SET_MODE_FILTER  = 1
	SECCOMP_GET_ACTION_AVAIL = 2
	SECCOMP_GET_NOTIF_SIZES  = 3

	/* Valid flags for SECCOMP_SET_MODE_FILTER */
	SECCOMP_FILTER_FLAG_TSYNC        = 1 << 0
	SECCOMP_FILTER_FLAG_LOG          = 1 << 1
	SECCOMP_FILTER_FLAG_SPEC_ALLOW   = 1 << 2
	SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH  = 1 << 4
	/* Received notifications wait in killable state (only respond to fatal signals) */
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV = 1 << 5

	/*
	 * All BPF programs must return a 32-bit value.
	 * The bottom 16-bits are for optional return data.
	 * The upper 16-bits are ordered from least permissive values to most,
	 * as a signed value (so 0x8000000 is negative).
	 *
	 * The ordering ensures that a min_t() over composed return values always
	 * selects the least permissive choice.
	 */
	SECCOMP_RET_KILL_PROCESS = 0x80000000 /* kill the process */
	SECCOMP_RET_KILL_THREAD  = 0x00000000 /* kill the thread */
	SECCOMP_RET_KILL         = SECCOMP_RET_KILL_THREAD
	SECCOMP_RET_TRAP         = 0x00030000 /* disallow and force a SIGSYS */
	SECCOMP_RET_ERRNO        = 0x00050000 /* returns an errno */
	SECCOMP_RET_USER_NOTIF   = 0x7fc00000 /* notifies userspace */
	SECCOMP_RET_TRACE        = 0x7ff00000 /* pass to a tracer or disallow */
	SECCOMP_RET_LOG          = 0x7ffc0000 /* allow after logging */
	SECCOMP_RET_ALLOW        = 0x7fff0000 /* allow */

	/* Masks for the return value sections. */
	SECCOMP_RET_ACTION_FULL = 0xffff0000
	SECCOMP_RET_ACTION      = 0x7fff0000
	SECCOMP_RET_DATA        = 0x0000ffff

	// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/elf-em.h
	// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/audit.h
	EM_X86_64          = 62 /* AMD x86-64 */
	__AUDIT_ARCH_64BIT = 0x80000000
	__AUDIT_ARCH_LE    = 0x40000000
	AUDIT_ARCH_X86_64  = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE

	BPF_LD   = 0x00
	BPF_W    = 0x00
	BPF_ABS  = 0x20
	BPF_JMP  = 0x05
	BPF_JEQ  = 0x10
	BPF_JEST = 0x40
	BPF_K    = 0x00
	BPF_RET  = 0x06
)

const (
	sys_read                    = 0
	sys_write                   = 1
	sys_open                    = 2
	sys_close                   = 3
	sys_newstat                 = 4
	sys_newfstat                = 5
	sys_newlstat                = 6
	sys_poll                    = 7
	sys_lseek                   = 8
	sys_mmap                    = 9
	sys_mprotect                = 10
	sys_munmap                  = 11
	sys_brk                     = 12
	sys_rt_sigaction            = 13
	sys_rt_sigprocmask          = 14
	sys_rt_sigreturn            = 15
	sys_ioctl                   = 16
	sys_pread64                 = 17
	sys_pwrite64                = 18
	sys_readv                   = 19
	sys_writev                  = 20
	sys_access                  = 21
	sys_pipe                    = 22
	sys_select                  = 23
	sys_sched_yield             = 24
	sys_mremap                  = 25
	sys_msync                   = 26
	sys_mincore                 = 27
	sys_madvise                 = 28
	sys_shmget                  = 29
	sys_shmat                   = 30
	sys_shmctl                  = 31
	sys_dup                     = 32
	sys_dup2                    = 33
	sys_pause                   = 34
	sys_nanosleep               = 35
	sys_getitimer               = 36
	sys_alarm                   = 37
	sys_setitimer               = 38
	sys_getpid                  = 39
	sys_sendfile64              = 40
	sys_socket                  = 41
	sys_connect                 = 42
	sys_accept                  = 43
	sys_sendto                  = 44
	sys_recvfrom                = 45
	sys_sendmsg                 = 46
	sys_recvmsg                 = 47
	sys_shutdown                = 48
	sys_bind                    = 49
	sys_listen                  = 50
	sys_getsockname             = 51
	sys_getpeername             = 52
	sys_socketpair              = 53
	sys_setsockopt              = 54
	sys_getsockopt              = 55
	sys_clone                   = 56
	sys_fork                    = 57
	sys_vfork                   = 58
	sys_execve                  = 59
	sys_exit                    = 60
	sys_wait4                   = 61
	sys_kill                    = 62
	sys_newuname                = 63
	sys_semget                  = 64
	sys_semop                   = 65
	sys_semctl                  = 66
	sys_shmdt                   = 67
	sys_msgget                  = 68
	sys_msgsnd                  = 69
	sys_msgrcv                  = 70
	sys_msgctl                  = 71
	sys_fcntl                   = 72
	sys_flock                   = 73
	sys_fsync                   = 74
	sys_fdatasync               = 75
	sys_truncate                = 76
	sys_ftruncate               = 77
	sys_getdents                = 78
	sys_getcwd                  = 79
	sys_chdir                   = 80
	sys_fchdir                  = 81
	sys_rename                  = 82
	sys_mkdir                   = 83
	sys_rmdir                   = 84
	sys_creat                   = 85
	sys_link                    = 86
	sys_unlink                  = 87
	sys_symlink                 = 88
	sys_readlink                = 89
	sys_chmod                   = 90
	sys_fchmod                  = 91
	sys_chown                   = 92
	sys_fchown                  = 93
	sys_lchown                  = 94
	sys_umask                   = 95
	sys_gettimeofday            = 96
	sys_getrlimit               = 97
	sys_getrusage               = 98
	sys_sysinfo                 = 99
	sys_times                   = 100
	sys_ptrace                  = 101
	sys_getuid                  = 102
	sys_syslog                  = 103
	sys_getgid                  = 104
	sys_setuid                  = 105
	sys_setgid                  = 106
	sys_geteuid                 = 107
	sys_getegid                 = 108
	sys_setpgid                 = 109
	sys_getppid                 = 110
	sys_getpgrp                 = 111
	sys_setsid                  = 112
	sys_setreuid                = 113
	sys_setregid                = 114
	sys_getgroups               = 115
	sys_setgroups               = 116
	sys_setresuid               = 117
	sys_getresuid               = 118
	sys_setresgid               = 119
	sys_getresgid               = 120
	sys_getpgid                 = 121
	sys_setfsuid                = 122
	sys_setfsgid                = 123
	sys_getsid                  = 124
	sys_capget                  = 125
	sys_capset                  = 126
	sys_rt_sigpending           = 127
	sys_rt_sigtimedwait         = 128
	sys_rt_sigqueueinfo         = 129
	sys_rt_sigsuspend           = 130
	sys_sigaltstack             = 131
	sys_utime                   = 132
	sys_mknod                   = 133
	sys_personality             = 135
	sys_ustat                   = 136
	sys_statfs                  = 137
	sys_fstatfs                 = 138
	sys_sysfs                   = 139
	sys_getpriority             = 140
	sys_setpriority             = 141
	sys_sched_setparam          = 142
	sys_sched_getparam          = 143
	sys_sched_setscheduler      = 144
	sys_sched_getscheduler      = 145
	sys_sched_get_priority_max  = 146
	sys_sched_get_priority_min  = 147
	sys_sched_rr_get_interval   = 148
	sys_mlock                   = 149
	sys_munlock                 = 150
	sys_mlockall                = 151
	sys_munlockall              = 152
	sys_vhangup                 = 153
	sys_modify_ldt              = 154
	sys_pivot_root              = 155
	sys_ni_syscall              = 156
	sys_prctl                   = 157
	sys_arch_prctl              = 158
	sys_adjtimex                = 159
	sys_setrlimit               = 160
	sys_chroot                  = 161
	sys_sync                    = 162
	sys_acct                    = 163
	sys_settimeofday            = 164
	sys_mount                   = 165
	sys_umount                  = 166
	sys_swapon                  = 167
	sys_swapoff                 = 168
	sys_reboot                  = 169
	sys_sethostname             = 170
	sys_setdomainname           = 171
	sys_iopl                    = 172
	sys_ioperm                  = 173
	sys_init_module             = 175
	sys_delete_module           = 176
	get_kernel_syms             = 177
	query_module                = 178
	sys_quotactl                = 179
	nfsservctl                  = 180
	sys_gettid                  = 186
	sys_readahead               = 187
	sys_setxattr                = 188
	sys_lsetxattr               = 189
	sys_fsetxattr               = 190
	sys_getxattr                = 191
	sys_lgetxattr               = 192
	sys_fgetxattr               = 193
	sys_listxattr               = 194
	sys_llistxattr              = 195
	sys_flistxattr              = 196
	sys_removexattr             = 197
	sys_lremovexattr            = 198
	sys_fremovexattr            = 199
	sys_tkill                   = 200
	sys_time                    = 201
	sys_futex                   = 202
	sys_sched_setaffinity       = 203
	sys_sched_getaffinity       = 204
	sys_io_setup                = 206
	sys_io_destroy              = 207
	sys_io_getevents            = 208
	sys_io_submit               = 209
	sys_io_cancel               = 210
	lookup_dcookie              = 212
	sys_epoll_create            = 213
	sys_remap_file_pages        = 216
	sys_getdents64              = 217
	sys_set_tid_address         = 218
	sys_restart_syscall         = 219
	sys_semtimedop              = 220
	sys_fadvise64               = 221
	sys_timer_create            = 222
	sys_timer_settime           = 223
	sys_timer_gettime           = 224
	sys_timer_getoverrun        = 225
	sys_timer_delete            = 226
	sys_clock_settime           = 227
	sys_clock_gettime           = 228
	sys_clock_getres            = 229
	sys_clock_nanosleep         = 230
	sys_exit_group              = 231
	sys_epoll_wait              = 232
	sys_epoll_ctl               = 233
	sys_tgkill                  = 234
	sys_utimes                  = 235
	sys_mbind                   = 237
	sys_set_mempolicy           = 238
	sys_get_mempolicy           = 239
	sys_mq_open                 = 240
	sys_mq_unlink               = 241
	sys_mq_timedsend            = 242
	sys_mq_timedreceive         = 243
	sys_mq_notify               = 244
	sys_mq_getsetattr           = 245
	sys_kexec_load              = 246
	sys_waitid                  = 247
	sys_add_key                 = 248
	sys_request_key             = 249
	sys_keyctl                  = 250
	sys_ioprio_set              = 251
	sys_ioprio_get              = 252
	sys_inotify_init            = 253
	sys_inotify_add_watch       = 254
	sys_inotify_rm_watch        = 255
	sys_migrate_pages           = 256
	sys_openat                  = 257
	sys_mkdirat                 = 258
	sys_mknodat                 = 259
	sys_fchownat                = 260
	sys_futimesat               = 261
	sys_newfstatat              = 262
	sys_unlinkat                = 263
	sys_renameat                = 264
	sys_linkat                  = 265
	sys_symlinkat               = 266
	sys_readlinkat              = 267
	sys_fchmodat                = 268
	sys_faccessat               = 269
	sys_pselect6                = 270
	sys_ppoll                   = 271
	sys_unshare                 = 272
	sys_set_robust_list         = 273
	sys_get_robust_list         = 274
	sys_splice                  = 275
	sys_tee                     = 276
	sys_sync_file_range         = 277
	sys_vmsplice                = 278
	sys_move_pages              = 279
	sys_utimensat               = 280
	sys_epoll_pwait             = 281
	sys_signalfd                = 282
	sys_timerfd_create          = 283
	sys_eventfd                 = 284
	sys_fallocate               = 285
	sys_timerfd_settime         = 286
	sys_timerfd_gettime         = 287
	sys_accept4                 = 288
	sys_signalfd4               = 289
	sys_eventfd2                = 290
	sys_epoll_create1           = 291
	sys_dup3                    = 292
	sys_pipe2                   = 293
	sys_inotify_init1           = 294
	sys_preadv                  = 295
	sys_pwritev                 = 296
	sys_rt_tgsigqueueinfo       = 297
	sys_perf_event_open         = 298
	sys_recvmmsg                = 299
	sys_fanotify_init           = 300
	sys_fanotify_mark           = 301
	sys_prlimit64               = 302
	sys_name_to_handle_at       = 303
	sys_open_by_handle_at       = 304
	sys_clock_adjtime           = 305
	sys_syncfs                  = 306
	sys_sendmmsg                = 307
	sys_setns                   = 308
	sys_getcpu                  = 309
	sys_process_vm_readv        = 310
	sys_process_vm_writev       = 311
	sys_kcmp                    = 312
	sys_finit_module            = 313
	sys_sched_setattr           = 314
	sys_sched_getattr           = 315
	sys_renameat2               = 316
	sys_seccomp                 = 317
	sys_getrandom               = 318
	sys_memfd_create            = 319
	sys_kexec_file_load         = 320
	sys_bpf                     = 321
	sys_execveat                = 322
	sys_userfaultfd             = 323
	sys_membarrier              = 324
	sys_mlock2                  = 325
	sys_copy_file_range         = 326
	sys_preadv2                 = 327
	sys_pwritev2                = 328
	sys_pkey_mprotect           = 329
	sys_pkey_alloc              = 330
	sys_pkey_free               = 331
	sys_statx                   = 332
	sys_io_pgetevents           = 333
	sys_rseq                    = 334
	sys_uretprobe               = 335
	sys_uprobe                  = 336
	sys_pidfd_send_signal       = 424
	sys_io_uring_setup          = 425
	sys_io_uring_enter          = 426
	sys_io_uring_register       = 427
	sys_open_tree               = 428
	sys_move_mount              = 429
	sys_fsopen                  = 430
	sys_fsconfig                = 431
	sys_fsmount                 = 432
	sys_fspick                  = 433
	sys_pidfd_open              = 434
	sys_clone3                  = 435
	sys_close_range             = 436
	sys_openat2                 = 437
	sys_pidfd_getfd             = 438
	sys_faccessat2              = 439
	sys_process_madvise         = 440
	sys_epoll_pwait2            = 441
	sys_mount_setattr           = 442
	sys_quotactl_fd             = 443
	sys_landlock_create_ruleset = 444
	sys_landlock_add_rule       = 445
	sys_landlock_restrict_self  = 446
	sys_memfd_secret            = 447
	sys_process_mrelease        = 448
	sys_futex_waitv             = 449
	sys_set_mempolicy_home_node = 450
	sys_cachestat               = 451
	sys_fchmodat2               = 452
	sys_map_shadow_stack        = 453
	sys_futex_wake              = 454
	sys_futex_wait              = 455
	sys_futex_requeue           = 456
	sys_statmount               = 457
	sys_listmount               = 458
	sys_lsm_get_self_attr       = 459
	sys_lsm_set_self_attr       = 460
	sys_lsm_list_modules        = 461
	sys_mseal                   = 462
	sys_setxattrat              = 463
	sys_getxattrat              = 464
	sys_listxattrat             = 465
	sys_removexattrat           = 466
	sys_open_tree_attr          = 467
	sys_file_getattr            = 468
	sys_file_setattr            = 469
	sys_listns                  = 470
	sys_rseq_slice_yield        = 471
)

func setSeccomp() error {
	deny := []int{
		sys_acct,
		sys_add_key,
		sys_bpf,
		sys_clock_adjtime,
		sys_clock_settime,
		sys_delete_module,
		sys_finit_module,
		get_kernel_syms,
		sys_get_mempolicy,
		sys_init_module,
		sys_ioperm,
		sys_iopl,
		sys_io_uring_enter,
		sys_io_uring_register,
		sys_io_uring_setup,
		sys_kcmp,
		sys_kexec_file_load,
		sys_kexec_load,
		sys_keyctl,
		lookup_dcookie,
		sys_mbind,
		sys_mount,
		sys_move_pages,
		nfsservctl,
		sys_open_by_handle_at,
		sys_perf_event_open,
		sys_personality,
		sys_pivot_root,
		sys_process_vm_readv,
		sys_process_vm_writev,
		sys_ptrace,
		query_module,
		sys_quotactl,
		sys_reboot,
		sys_request_key,
		sys_set_mempolicy,
		sys_setns,
		sys_settimeofday,
		sys_time,
		sys_swapon,
		sys_swapoff,
		sys_sysfs,
		sys_ni_syscall,
		sys_umount,
		sys_unshare,
		sys_userfaultfd,
		sys_ustat,
	}

	// arch validation
	filter := []syscall.SockFilter{
		// about 4: seccomp_data offset size
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/seccomp.h
		bpfStmt(BPF_LD|BPF_W|BPF_ABS, 4),                        // VAR = {seccomp_data:arch}
		bpfJump(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0), // if (VAR == AUDIT_ARCH_X86_64) Skip1Instruction else Skip0Instruction
		bpfStmt(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),        // kill process
		bpfStmt(BPF_LD|BPF_W|BPF_ABS, 0),                        // VAR = {NR(SyscallNumber)} // end of validation, start of filtering
	}

	// sys_clone validation
	filter = append(filter,
		bpfJump(BPF_JMP|BPF_JEQ|BPF_K, uint32(sys_clone), 0, 3), // if (VAR == sys_clone) Skip0Instruction else Skip3Instructions
		bpfStmt(BPF_LD|BPF_W|BPF_ABS, 16),                       // VAR = {seccomp_data:args[0]}
		bpfJump(BPF_JMP|BPF_JEST|BPF_K, uint32(syscall.CLONE_NEWNS|
			syscall.CLONE_NEWUTS|
			syscall.CLONE_NEWIPC|
			syscall.CLONE_NEWPID|
			syscall.CLONE_NEWNET|
			syscall.CLONE_NEWCGROUP), 0, 1), // if (VAR == syscall.CLONE_XXX) Skip0Instruction else Skip1Instruction
		bpfStmt(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|uint32(syscall.EPERM)), // ERROR
		bpfStmt(BPF_LD|BPF_W|BPF_ABS, 0),                                // VAR = {NR(SyscallNumber)} // end of validation, start of filtering
	)

	for _, nr := range deny {
		filter = append(filter,
			bpfJump(BPF_JMP|BPF_JEQ|BPF_K, uint32(nr), 0, 1),                // if (VAR == NR) Skip0Instruction else Skip1Instruction
			bpfStmt(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|uint32(syscall.EPERM)), // ERROR
		)
	}

	filter = append(filter, bpfStmt(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)) // allow other syscalls

	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	return prctl(prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog)), 0, 0)
}

func bpfStmt(code uint16, k uint32) syscall.SockFilter {
	return syscall.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt uint8, jf uint8) syscall.SockFilter {
	return syscall.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

func setPrivileges() {
	const PR_CAPBSET_DROP = 24
	const PR_SET_NO_NEW_PRIVS = 38
	const PR_CAP_AMBIENT = 47
	const PR_CAP_AMBIENT_CLEAR_ALL = 4

	must(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
	must(clearAllInheritableCaps())
	must(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))

	keep := map[int]bool{
		CAP_CHOWN:            true,
		CAP_DAC_OVERRIDE:     true,
		CAP_FOWNER:           true,
		CAP_FSETID:           true,
		CAP_KILL:             true,
		CAP_SETGID:           true,
		CAP_SETUID:           true,
		CAP_SETPCAP:          true,
		CAP_NET_BIND_SERVICE: true,
		CAP_NET_RAW:          true,
		CAP_SYS_CHROOT:       true,
		CAP_MKNOD:            true,
		CAP_AUDIT_WRITE:      true,
		CAP_SETFCAP:          true,
	}

	for cap := 0; cap <= CAP_LAST_CAP; cap++ {
		if keep[cap] {
			continue
		}
		must(prctl(PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0))
	}
}
