//go:build !windows

package actions

import "fmt"

func KillProcess(pid int) error {
	return fmt.Errorf("kill_process is windows-only in this build")
}

func IsolateEgress() error {
	return fmt.Errorf("isolate_egress is windows-only in this build")
}

