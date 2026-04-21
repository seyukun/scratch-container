package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
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
