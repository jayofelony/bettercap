//go:build darwin

package ssh_proxy

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// getOriginalDst retrieves the original destination for a redirected connection
// on macOS by querying the pf state table via `pfctl -s state`.
//
// When pf `rdr` redirects a connection, the state table contains entries like:
//   ALL tcp 192.168.1.50:54321 -> 192.168.1.100:22 -> 192.168.1.1:2222
//
// We look for the entry matching our connection's local+remote and extract
// the middle address (the original destination).
func getOriginalDst(conn net.Conn) (string, error) {
	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()

	// Parse what we know about this connection
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse remote addr: %v", err)
	}
	_, localPort, err := net.SplitHostPort(localAddr)
	if err != nil {
		return "", fmt.Errorf("failed to parse local addr: %v", err)
	}

	// Query pf state table
	out, err := exec.Command("pfctl", "-s", "state").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pfctl -s state failed: %v (output: %s)", err, string(out))
	}

	// Parse state table looking for our connection
	// Format: ALL tcp <src> -> <original_dst> -> <rdr_dst>  ESTABLISHED:ESTABLISHED
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()

		// We need lines with our remote host (the client) and our local port (proxy)
		if !strings.Contains(line, remoteHost) {
			continue
		}
		if !strings.Contains(line, ":"+localPort) {
			continue
		}

		// Try to parse: "ALL tcp <src> -> <orig_dst> -> <rdr_dst> ..."
		fields := strings.Fields(line)
		// Find the arrow pattern: fields should contain src, "->", origdst, "->", rdrdst
		arrowPositions := []int{}
		for i, f := range fields {
			if f == "->" {
				arrowPositions = append(arrowPositions, i)
			}
		}

		if len(arrowPositions) >= 2 {
			// The field before the first arrow is the source
			// The field between the two arrows is the original destination
			origDstIdx := arrowPositions[0] + 1
			if origDstIdx < len(fields) {
				origDst := fields[origDstIdx]
				// Validate it looks like host:port
				if _, _, err := net.SplitHostPort(origDst); err == nil {
					return origDst, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find original destination in pf state table for %s -> %s", remoteAddr, localAddr)
}
