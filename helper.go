package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func hostUserIDs() (int, int, error) {
	hostUID := os.Getuid()
	hostGID := os.Getgid()

	if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
		uid, err := strconv.Atoi(sudoUID)
		if err != nil {
			return 0, 0, fmt.Errorf("parse SUDO_UID: %w", err)
		}
		hostUID = uid
	}
	if sudoGID := os.Getenv("SUDO_GID"); sudoGID != "" {
		gid, err := strconv.Atoi(sudoGID)
		if err != nil {
			return 0, 0, fmt.Errorf("parse SUDO_GID: %w", err)
		}
		hostGID = gid
	}

	return hostUID, hostGID, nil
}

func userNamespaceMappings() ([]syscall.SysProcIDMap, []syscall.SysProcIDMap, error) {
	hostUID, hostGID, err := hostUserIDs()
	if err != nil {
		return nil, nil, err
	}

	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		return nil, nil, fmt.Errorf("SUDO_USER or USER is required for subuid/subgid lookup")
	}

	subUIDStart, subUIDSize, err := subIDRange("/etc/subuid", user)
	if err != nil {
		return nil, nil, err
	}
	subGIDStart, subGIDSize, err := subIDRange("/etc/subgid", user)
	if err != nil {
		return nil, nil, err
	}

	uidSize := subUIDSize - 1
	gidSize := subGIDSize - 1
	if uidSize < 65534 || gidSize < 65534 {
		return nil, nil, fmt.Errorf("subuid/subgid range for %q is too small", user)
	}

	uidMappings := []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: hostUID, Size: 1},
		{ContainerID: 1, HostID: subUIDStart, Size: uidSize},
	}
	gidMappings := []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: hostGID, Size: 1},
		{ContainerID: 1, HostID: subGIDStart, Size: gidSize},
	}

	return uidMappings, gidMappings, nil
}

func subIDRange(path string, name string) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) != 3 || fields[0] != name {
			continue
		}

		start, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, 0, fmt.Errorf("parse %s start for %q: %w", path, name, err)
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, 0, fmt.Errorf("parse %s size for %q: %w", path, name, err)
		}
		return start, size, nil
	}

	return 0, 0, fmt.Errorf("%s has no entry for %q", path, name)
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
