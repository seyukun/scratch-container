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
	N_ROOTFS      = 2
	N_ID          = 3
	N_HOSTNAME    = 4
	N_IPRANGE     = 5
	N_ROUTEIP     = 6
	N_MASTERBRNIC = 7
	N_CPUQUOTA    = 8
	N_CPUPERIOD   = 9
	N_MEM         = 10
	N_CMD         = 11
)

func main() {
	if len(os.Args) < 12 {
		panic("usage: run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]")
	}

	switch os.Args[1] {
	case "run":
		os.Exit(run())
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

func run() int {
	id := os.Args[N_ID]
	containerIpRange := os.Args[N_IPRANGE]
	containerDefaultRouteIP := os.Args[N_ROUTEIP]
	hostMasterBridgeNic := os.Args[N_MASTERBRNIC]
	containerTempNic := rand.Text()[:8]

	// Setup network namespace and veth pair
	defer command("ip", "netns", "del", id).Run()
	if err := command("ip", "netns", "add", id).Run(); err != nil {
		must(err)
		return 1
	}
	defer command("ip", "link", "del", id).Run()
	if err := command("ip", "link", "add", id, "type", "veth", "peer", "name", containerTempNic).Run(); err != nil {
		must(err)
		return 1
	}
	ipCommands := [][]string{
		{"link", "set", containerTempNic, "netns", id},
		{"link", "set", id, "master", hostMasterBridgeNic},
		{"link", "set", id, "up"},
		{"netns", "exec", id, "ip", "link", "set", containerTempNic, "name", "eth0"},
		{"netns", "exec", id, "ip", "addr", "add", containerIpRange, "dev", "eth0"},
		{"netns", "exec", id, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", id, "ip", "link", "set", "eth0", "up"},
		{"netns", "exec", id, "ip", "route", "add", "default", "via", containerDefaultRouteIP},
	}

	for _, args := range ipCommands {
		must(command("ip", args...).Run())
	}

	exe, err := os.Executable()
	must(err)

	cmd := exec.Command("ip", append([]string{"netns", "exec", os.Args[N_ID], exe, "child"}, os.Args[2:]...)...)

	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWIPC,
	}

	must(cmd.Start())

	cgroup := filepath.Join("/sys/fs/cgroup", os.Args[N_ID])
	defer os.Remove(filepath.Join("/sys/fs/cgroup", os.Args[N_ID]))
	must(os.MkdirAll(cgroup, 0755))
	must(os.WriteFile(filepath.Join(cgroup, "pids.max"), []byte("64"), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "cpu.max"), []byte(os.Args[N_CPUQUOTA]+" "+os.Args[N_CPUPERIOD]), 0700))
	must(os.WriteFile(filepath.Join(cgroup, "memory.max"), []byte(os.Args[N_MEM]), 0700))

	return exitCode(cmd.Wait())
}

func command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd
}

func child() {
	fmt.Printf("Running %v \n", os.Args[N_CMD:])

	rootfs := os.Args[N_ROOTFS]

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

	must(syscall.Mknod("/dev/null", syscall.S_IFCHR|0666, 1<<8|3))
	must(syscall.Mknod("/dev/zero", syscall.S_IFCHR|0666, 1<<8|5))
	must(syscall.Mknod("/dev/full", syscall.S_IFCHR|0666, 1<<8|7))
	must(syscall.Mknod("/dev/random", syscall.S_IFCHR|0666, 1<<8|8))
	must(syscall.Mknod("/dev/urandom", syscall.S_IFCHR|0666, 1<<8|9))
	must(syscall.Mknod("/dev/tty", syscall.S_IFCHR|0666, 5<<8))
	must(syscall.Mknod("/dev/ptmx", syscall.S_IFCHR|0666, 5<<8|2))

	must(syscall.Unmount("/oldroot", syscall.MNT_DETACH))
	must(os.Remove("/oldroot"))

	must(syscall.Sethostname([]byte(os.Args[N_HOSTNAME])))

	setPrivileges()
	must(setSeccomp())

	cmd := exec.Command(os.Args[N_CMD], os.Args[N_CMD+1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	os.Exit(exitCode(cmd.Run()))
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
