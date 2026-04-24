//go:build linux

package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
	if len(os.Args) < 2 {
		panic("usage: run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]")
	}

	switch os.Args[1] {
	case "run":
		os.Exit(run())
	case "child":
		os.Exit(child())
	case "exec":
		os.Exit(execRun())
	case "exec-child":
		os.Exit(execChild())
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
	if len(os.Args) < 12 {
		panic("usage: run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]")
	}

	id := os.Args[N_ID]
	containerIpRange := os.Args[N_IPRANGE]
	containerDefaultRouteIP := os.Args[N_ROUTEIP]
	hostMasterBridgeNic := os.Args[N_MASTERBRNIC]
	hostNic := "veth-" + rand.Text()[:10]
	containerTempNic := rand.Text()[:15]

	if _, err := os.Stat(filepath.Join("/var/run/netns", id)); err == nil {
		fmt.Fprintf(os.Stderr, "network namespace %q already exists\n", id)
		return 1
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "failed to stat network namespace %q: %v\n", id, err)
		return 1
	}

	uidMappings, gidMappings, err := userNamespaceMappings()
	must(err)

	readyR, readyW, err := os.Pipe()
	must(err)
	defer readyR.Close()
	defer readyW.Close()

	cmd := exec.Command("/proc/self/exe", append([]string{"child"}, os.Args[2:]...)...)
	{
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.ExtraFiles = []*os.File{readyR}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWPID |
				syscall.CLONE_NEWUTS |
				syscall.CLONE_NEWNS |
				syscall.CLONE_NEWIPC |
				syscall.CLONE_NEWUSER |
				syscall.CLONE_NEWNET,
			Setpgid:                    true,
			UidMappings:                uidMappings,
			GidMappings:                gidMappings,
			GidMappingsEnableSetgroups: true,
			Credential:                 &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{0}},
		}
		must(cmd.Start())
	}

	signalEnd := make(chan struct{})
	go signalForward(cmd, signalEnd)

	readyR.Close()

	{
		must(command("ip", "netns", "attach", id, strconv.Itoa(cmd.Process.Pid)).Run())
		defer command("ip", "netns", "del", id).Run()
		must(command("ip", "link", "add", hostNic, "type", "veth", "peer", "name", containerTempNic).Run())
		defer command("ip", "link", "del", hostNic).Run()
		ipCommands := [][]string{
			{"link", "set", containerTempNic, "netns", id},
			{"link", "set", hostNic, "master", hostMasterBridgeNic},
			{"link", "set", hostNic, "up"},
			{"netns", "exec", id, "ip", "link", "set", containerTempNic, "name", "eth0"},
			{"netns", "exec", id, "ip", "addr", "add", containerIpRange, "dev", "eth0"},
			{"netns", "exec", id, "ip", "link", "set", "lo", "up"},
			{"netns", "exec", id, "ip", "link", "set", "eth0", "up"},
			{"netns", "exec", id, "ip", "route", "add", "default", "via", containerDefaultRouteIP},
		}
		for _, args := range ipCommands {
			must(command("ip", args...).Run())
		}
	}

	readyW.Close()

	{
		cgroup := filepath.Join("/sys/fs/cgroup", os.Args[N_ID])
		defer os.Remove(filepath.Join("/sys/fs/cgroup", os.Args[N_ID]))
		must(os.MkdirAll(cgroup, 0755))
		must(os.WriteFile(filepath.Join(cgroup, "pids.max"), []byte("64"), 0700))
		must(os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0700))
		must(os.WriteFile(filepath.Join(cgroup, "cpu.max"), []byte(os.Args[N_CPUQUOTA]+" "+os.Args[N_CPUPERIOD]), 0700))
		must(os.WriteFile(filepath.Join(cgroup, "memory.max"), []byte(os.Args[N_MEM]), 0700))
	}

	result := cmd.Wait()
	close(signalEnd)
	return exitCode(result)
}

func child() int {
	fmt.Printf("Running %v \n", os.Args[N_CMD:])

	// Wait for parent network to be Ready
	if fReady := os.NewFile(3, "NETWORK_READY"); fReady == nil {
		panic("failed to open network ready pipe")
	} else {
		defer fReady.Close()
		if _, err := io.ReadAll(fReady); err != nil {
			panic(err)
		}
	}

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

	masked := []string{
		"/proc/acpi",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sysrq-trigger",
		"/sys/devices/virtual/powercap",
		"/sys/firmware",
		"/sys/fs/cgroup",
		"/sys/kernel/config",
		"/sys/kernel/debug",
		"/sys/kernel/security",
		"/sys/kernel/tracing",
		"/sys/module",
		"/sys/power",
	}
	for _, target := range masked {
		info, err := os.Stat(target)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			must(err)
		}

		if info.IsDir() {
			must(syscall.Mount("tmpfs", target, "tmpfs", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "mode=755"))
			continue
		}
		must(syscall.Mount("/oldroot/dev/null", target, "", syscall.MS_BIND|syscall.MS_RDONLY, ""))
	}

	readonly := []string{
		"/proc/asound",
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysvipc",
	}
	for _, target := range readonly {
		if _, err := os.Stat(target); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			must(err)
		}
		must(syscall.Mount(target, target, "", syscall.MS_BIND|syscall.MS_REC, ""))
		must(syscall.Mount(target, target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_REC, ""))
	}

	must(syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID, "mode=755"))
	must(os.MkdirAll("/dev/pts", 0755))
	must(os.MkdirAll("/dev/shm", 0755))
	must(syscall.Mount("devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=666,mode=620,gid=0"))
	must(syscall.Mount("tmpfs", "/dev/shm", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=1777,size=64m"))
	must(syscall.Mount("tmpfs", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=755"))

	must(os.Chmod("/tmp", 01777))

	for _, dev := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		target := filepath.Join("/dev", dev)
		source := filepath.Join("/oldroot/dev", dev)

		if f, err := os.OpenFile(target, os.O_CREATE, 0666); err != nil {
			must(err)
		} else {
			if err := f.Close(); err != nil {
				must(err)
			} else {
				if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
					must(err)
				}
			}
		}
	}
	must(os.Symlink("pts/ptmx", "/dev/ptmx"))

	must(syscall.Unmount("/oldroot", syscall.MNT_DETACH))
	must(os.Remove("/oldroot"))

	must(syscall.Sethostname([]byte(os.Args[N_HOSTNAME])))

	setPrivileges()
	must(setSeccomp())

	cmd := exec.Command(os.Args[N_CMD], os.Args[N_CMD+1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	return exitCode(cmd.Run())
}

func execRun() int {
	if len(os.Args) < 4 {
		panic("usage: exec <id> <cmd> [args...]")
	}

	id := os.Args[2]
	pid := ""
	if data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", id, "cgroup.procs")); err != nil {
		must(err)
	} else {
		pids := strings.Fields(string(data))
		if len(pids) == 0 {
			fmt.Fprintf(os.Stderr, "container %q has no processes\n", id)
			return 1
		}
		pid = pids[0]
	}

	args := []string{
		"--target", pid,
		"--user",
		"--mount",
		"--uts",
		"--ipc",
		"--net",
		"--pid",
		"--root=" + filepath.Join("/proc", pid, "root"),
		"--setuid", "0",
		"--setgid", "0",
		"/proc/self/fd/3",
		"exec-child",
	}
	args = append(args, os.Args[3:]...)

	exe, err := os.Open("/proc/self/exe")
	must(err)
	defer exe.Close()

	cmd := exec.Command("nsenter", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{exe}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	must(cmd.Start())

	signalEnd := make(chan struct{})
	go signalForward(cmd, signalEnd)

	must(os.WriteFile(filepath.Join("/sys/fs/cgroup", id, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0700))

	result := cmd.Wait()
	close(signalEnd)
	return exitCode(result)
}

func execChild() int {
	if len(os.Args) < 3 {
		panic("usage: exec-child <cmd> [args...]")
	}

	setPrivileges()
	must(setSeccomp())

	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return exitCode(cmd.Run())
}

func signalForward(cmd *exec.Cmd, end chan struct{}) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(signals)

	for {
		select {
		case sig := <-signals:
			if cmd.Process == nil {
				continue
			}
			if sysSig, ok := sig.(syscall.Signal); ok {
				target := cmd.Process.Pid
				if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid {
					target = -target
				}
				syscall.Kill(target, sysSig)
			}
		case <-end:
			return
		}
	}
}
