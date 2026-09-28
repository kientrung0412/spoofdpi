//go:build !windows

package netutil

import "syscall"

func setsockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, value)
}
