//go:build linux

package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

const linuxCapabilitiesVersion3 = 0x20080522

type capUserHeader struct {
	Version uint32
	Pid     int32
}

type capUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

const (
	CAP_CHOWN              = 0
	CAP_DAC_OVERRIDE       = 1
	CAP_DAC_READ_SEARCH    = 2
	CAP_FOWNER             = 3
	CAP_FSETID             = 4
	CAP_KILL               = 5
	CAP_SETGID             = 6
	CAP_SETUID             = 7
	CAP_SETPCAP            = 8
	CAP_LINUX_IMMUTABLE    = 9
	CAP_NET_BIND_SERVICE   = 10
	CAP_NET_BROADCAST      = 11
	CAP_NET_ADMIN          = 12
	CAP_NET_RAW            = 13
	CAP_IPC_LOCK           = 14
	CAP_IPC_OWNER          = 15
	CAP_SYS_MODULE         = 16
	CAP_SYS_RAWIO          = 17
	CAP_SYS_CHROOT         = 18
	CAP_SYS_PTRACE         = 19
	CAP_SYS_PACCT          = 20
	CAP_SYS_ADMIN          = 21
	CAP_SYS_BOOT           = 22
	CAP_SYS_NICE           = 23
	CAP_SYS_RESOURCE       = 24
	CAP_SYS_TIME           = 25
	CAP_SYS_TTY_CONFIG     = 26
	CAP_MKNOD              = 27
	CAP_LEASE              = 28
	CAP_AUDIT_WRITE        = 29
	CAP_AUDIT_CONTROL      = 30
	CAP_SETFCAP            = 31
	CAP_MAC_OVERRIDE       = 32
	CAP_MAC_ADMIN          = 33
	CAP_SYSLOG             = 34
	CAP_WAKE_ALARM         = 35
	CAP_BLOCK_SUSPEND      = 36
	CAP_AUDIT_READ         = 37
	CAP_PERFMON            = 38
	CAP_BPF                = 39
	CAP_CHECKPOINT_RESTORE = 40
	CAP_LAST_CAP           = CAP_CHECKPOINT_RESTORE
)

const (
	NROOTFS      = 2
	NID          = 3
	NHOSTNAME    = 4
	NIPRANGE     = 5
	NROUTEIP     = 6
	NMASTERBRNIC = 7
	NCPUQUOTA    = 8
	NCPUPERIOD   = 9
	NMEM         = 10
	NCMD         = 11
)

func main() {
	if len(os.Args) < 12 {
		panic("usage: run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]")
	}

	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	default:
		panic("help")
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func run() {
	must(setupNetwork())

	exe, err := os.Executable()
	must(err)

	cmd := exec.Command("ip", append([]string{"netns", "exec", os.Args[NID], exe, "child"}, os.Args[2:]...)...)

	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWIPC,
	}

	must(cmd.Start())

	cgroup(cmd.Process.Pid)
	code := exitCode(cmd.Wait())
	cleanupNetwork()
	_ = os.Remove(filepath.Join("/sys/fs/cgroup", os.Args[NID]))
	os.Exit(code)
}

func setupNetwork() error {
	id := os.Args[NID]
	contIPRange := os.Args[NIPRANGE]
	routeIP := os.Args[NROUTEIP]
	masterBRNIC := os.Args[NMASTERBRNIC]
	tmpNIC := rand.Text()[:8]

	commands := [][]string{
		{"netns", "add", id},
		{"link", "add", id, "type", "veth", "peer", "name", tmpNIC},
		{"link", "set", tmpNIC, "netns", id},
		{"link", "set", id, "master", masterBRNIC},
		{"link", "set", id, "up"},
		{"netns", "exec", id, "ip", "link", "set", tmpNIC, "name", "eth0"},
		{"netns", "exec", id, "ip", "addr", "add", contIPRange, "dev", "eth0"},
		{"netns", "exec", id, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", id, "ip", "link", "set", "eth0", "up"},
		{"netns", "exec", id, "ip", "route", "add", "default", "via", routeIP},
	}

	for _, args := range commands {
		if err := command("ip", args...).Run(); err != nil {
			cleanupNetwork()
			return err
		}
	}

	return nil
}

func cleanupNetwork() {
	id := os.Args[NID]
	_ = command("ip", "link", "del", id).Run()
	_ = command("ip", "netns", "del", id).Run()
}

func command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd
}

func cgroup(pid int) {
	cgroup := filepath.Join("/sys/fs/cgroup", os.Args[NID])
	must(os.MkdirAll(cgroup, 0755))
	must(os.WriteFile(filepath.Join(cgroup, "pids.max"), []byte("64"), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "cpu.max"), []byte(os.Args[NCPUQUOTA]+" "+os.Args[NCPUPERIOD]), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "memory.max"), []byte(os.Args[NMEM]), 0700))
}

func child() {
	fmt.Printf("Running %v \n", os.Args[NCMD:])

	rootfs := os.Args[NROOTFS]

	must(syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""))
	must(syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""))

	for _, dir := range []string{"proc", "sys", "dev", "run", "tmp", "oldroot"} {
		must(os.MkdirAll(filepath.Join(rootfs, dir), 0755))
	}

	oldroot := filepath.Join(rootfs, "oldroot")
	must(syscall.PivotRoot(rootfs, oldroot))
	must(os.Chdir("/"))

	must(syscall.Mount("proc", "/proc", "proc", 0, ""))
	must(syscall.Mount("sysfs", "/sys", "sysfs", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""))

	must(syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID, "mode=755"))
	must(os.MkdirAll("/dev/pts", 0755))
	must(os.MkdirAll("/dev/shm", 0755))
	must(syscall.Mount("devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=666,mode=620,gid=5"))
	must(syscall.Mount("tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777,size=64m"))

	must(os.Chmod("/tmp", 01777))
	mknod("/dev/null", 0666, 1, 3)
	mknod("/dev/zero", 0666, 1, 5)
	mknod("/dev/full", 0666, 1, 7)
	mknod("/dev/random", 0666, 1, 8)
	mknod("/dev/urandom", 0666, 1, 9)
	mknod("/dev/tty", 0666, 5, 0)
	mknod("/dev/ptmx", 0666, 5, 2)

	must(syscall.Unmount("/oldroot", syscall.MNT_DETACH))
	must(os.Remove("/oldroot"))

	must(syscall.Sethostname([]byte(os.Args[NHOSTNAME])))

	setPrivileges()
	must(setSeccomp())

	cmd := exec.Command(os.Args[NCMD], os.Args[NCMD+1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	safetyExit(cmd.Run())
}

func safetyExit(err error) {
	os.Exit(exitCode(err))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return 128 + int(status.Signal())
			}
			return status.ExitStatus()
		}
	}

	must(err)
	return 1
}

func clearAllInheritableCaps() error {
	header := capUserHeader{Version: linuxCapabilitiesVersion3}
	data := [2]capUserData{}

	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}

	data[0].Inheritable = 0
	data[1].Inheritable = 0

	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}

	return nil
}

func prctl(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) error {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(option), arg2, arg3, arg4, arg5, 0); errno != 0 {
		return errno
	}
	return nil
}

func mknod(path string, perm uint32, major int, minor int) {
	dev := major<<8 | minor
	must(syscall.Mknod(path, syscall.S_IFCHR|perm, dev))
}
