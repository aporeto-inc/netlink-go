// +build linux

package syscallwrappers

import "syscall"

type syscalltypes struct {
}

// NewSyscalls is used to return Syscall struct
func NewSyscalls() Syscalls {
	return &syscalltypes{}
}

func (p *syscalltypes) Bind(fd int, sa syscall.Sockaddr) error {
	if syscall.Bind(fd, sa) != nil {
		return syscall.Bind(fd, sa)
	}
	return nil
}

func (p *syscalltypes) Socket(domain, typ, proto int) (int, error) {
	fd, err := syscall.Socket(domain, typ, proto)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func (p *syscalltypes) SetsockoptInt(fd, level, opt int, value int) error {
	if syscall.SetsockoptInt(fd, level, opt, value) != nil {
		return syscall.SetsockoptInt(fd, level, opt, value)
	}
	return nil
}

func (p *syscalltypes) Close(fd int) error {
	if syscall.Close(fd) != nil {
		return syscall.Close(fd)
	}
	return nil
}

func (p *syscalltypes) Recvfrom(fd int, pa []byte, flags int) (int, syscall.Sockaddr, error) {
	n, from, err := syscall.Recvfrom(fd, pa, flags)
	if err != nil {
		return -1, nil, err
	}
	return n, from, nil
}

func (p *syscalltypes) Sendto(fd int, pa []byte, flags int, to syscall.Sockaddr) error {
	if syscall.Sendto(fd, pa, flags, to) != nil {
		return syscall.Sendto(fd, pa, flags, to)
	}
	return nil
}

func (p *syscalltypes) Syscall(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	r1, r2, err := syscall.Syscall(trap, a1, a2, a3)
	if err != 0 {
		return 0, 0, err
	}
	return r1, r2, 0
}
