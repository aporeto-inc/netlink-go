package syscallwrappers

import "syscall"

// Syscalls interface will have the methods for syscall system functions used in nfqueue
type Syscalls interface {
	// Bind will bind to a PF family
	Bind(fd int, sa syscall.Sockaddr) error
	// Socket will open a new socket
	Socket(domain, typ, proto int) (int, error)
	// SetsockoptInt will be used to set socket options
	SetsockoptInt(fd, level, opt int, value int) error
	// Close will close the current socket
	Close(fd int) error
	// Recvfrom is used to receive message from Socket
	Recvfrom(fd int, p []byte, flags int) (int, syscall.Sockaddr, error)
	// Sendto is used to send message via socket
	Sendto(fd int, p []byte, flags int, to syscall.Sockaddr) error
	// Syscall is used as wrapper for syscall.SYS_SENDMSG
	Syscall(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno)
}
