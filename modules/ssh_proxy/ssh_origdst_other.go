//go:build !linux && !darwin

package ssh_proxy

import (
	"fmt"
	"net"
)

// getOriginalDst is a stub for platforms where NAT destination lookup
// is not implemented. Use the ssh.address parameter instead.
func getOriginalDst(conn net.Conn) (string, error) {
	return "", fmt.Errorf("automatic original destination detection is not supported on this platform; set ssh.address explicitly")
}
