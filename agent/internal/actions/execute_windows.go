//go:build windows

package actions

import (
	"errors"
	"fmt"
	"os"
)

var protectedPIDs = map[int]struct{}{
	0: {},
	4: {},
}

func KillProcess(pid int) error {
	if _, protected := protectedPIDs[pid]; protected {
		return errors.New("refusing to kill protected pid")
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

func IsolateEgress() error {
	return fmt.Errorf("isolate_egress not implemented yet on windows")
}

