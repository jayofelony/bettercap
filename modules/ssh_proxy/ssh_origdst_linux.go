//go:build linux

package ssh_proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	// SO_ORIGINAL_DST is the sockopt to retrieve the original destination
	// from netfilter REDIRECT / DNAT rules.
	soOriginalDst = 80 // SO_ORIGINAL_DST
)

// getOriginalDst retrieves the original destination address from the Linux
// netfilter conntrack table via getsockopt(SO_ORIGINAL_DST).
func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("failed to get raw conn: %v", err)
	}

	var origAddr syscall.RawSockaddrInet4
	var sysErr error

	err = rawConn.Control(func(fd uintptr) {
		addrLen := uint32(unsafe.Sizeof(origAddr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			soOriginalDst,
			uintptr(unsafe.Pointer(&origAddr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			sysErr = errno
		}
	})

	if err != nil {
		return "", fmt.Errorf("rawConn.Control failed: %v", err)
	}
	if sysErr != nil {
		return "", fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", sysErr)
	}

	// origAddr.Port is in network byte order (big-endian)
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&origAddr.Port))[:])
	ip := net.IPv4(origAddr.Addr[0], origAddr.Addr[1], origAddr.Addr[2], origAddr.Addr[3])

	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}
