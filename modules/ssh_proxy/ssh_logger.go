package ssh_proxy

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// logData logs plaintext channel data to the bettercap event stream.
// For client→server this is typically keystrokes / commands.
// For server→client this is typically shell output.
func (mod *SSHProxy) logData(channelID, direction string, data []byte) {
	if len(data) == 0 {
		return
	}

	// Try to render as printable text, falling back to hex for binary data
	display := sanitizeForLog(data)

	mod.Info("[%s] %s DATA (%d bytes): %s",
		channelID, direction, len(data), display)
}

// logRequest logs SSH channel requests with decoded payloads where possible.
func (mod *SSHProxy) logRequest(channelID, direction string, req *ssh.Request) {
	extra := ""

	switch req.Type {
	case "exec":
		// exec payload is: uint32 len + string command
		if cmd, err := parseString(req.Payload); err == nil {
			extra = fmt.Sprintf(" command=%q", cmd)
			mod.Info("[%s] >>> EXEC: %s", channelID, cmd)
		}

	case "shell":
		mod.Info("[%s] >>> SHELL requested", channelID)

	case "subsystem":
		if sub, err := parseString(req.Payload); err == nil {
			extra = fmt.Sprintf(" subsystem=%q", sub)
			mod.Info("[%s] >>> SUBSYSTEM: %s", channelID, sub)
		}

	case "pty-req":
		if term, w, h, err := parsePtyReq(req.Payload); err == nil {
			extra = fmt.Sprintf(" term=%s size=%dx%d", term, w, h)
		}

	case "env":
		if name, val, err := parseEnv(req.Payload); err == nil {
			extra = fmt.Sprintf(" %s=%q", name, val)
		}

	case "window-change":
		if w, h, err := parseWindowChange(req.Payload); err == nil {
			extra = fmt.Sprintf(" size=%dx%d", w, h)
		}

	case "exit-status":
		if len(req.Payload) >= 4 {
			code := binary.BigEndian.Uint32(req.Payload[:4])
			extra = fmt.Sprintf(" code=%d", code)
			mod.Info("[%s] >>> EXIT STATUS: %d", channelID, code)
		}

	case "exit-signal":
		if sig, err := parseString(req.Payload); err == nil {
			extra = fmt.Sprintf(" signal=%s", sig)
			mod.Info("[%s] >>> EXIT SIGNAL: %s", channelID, sig)
		}
	}

	mod.Debug("[%s] %s request: type=%s wantReply=%v%s",
		channelID, direction, req.Type, req.WantReply, extra)
}

// sanitizeForLog converts bytes to a printable string, replacing control
// characters and non-UTF8 sequences with escape notation.
func sanitizeForLog(data []byte) string {
	if !utf8.Valid(data) {
		// Binary data — show hex summary
		if len(data) > 64 {
			return fmt.Sprintf("[binary %d bytes: %x...]", len(data), data[:64])
		}
		return fmt.Sprintf("[binary %d bytes: %x]", len(data), data)
	}

	var b strings.Builder
	for _, r := range string(data) {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == '\x1b':
			b.WriteString("\\e")
		case unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t':
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseString extracts an SSH string (uint32 length-prefixed) from a payload.
func parseString(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", fmt.Errorf("payload too short")
	}
	l := binary.BigEndian.Uint32(payload[:4])
	if uint32(len(payload)-4) < l {
		return "", fmt.Errorf("payload truncated")
	}
	return string(payload[4 : 4+l]), nil
}

// parsePtyReq decodes a pty-req payload: string TERM, uint32 width-chars,
// uint32 height-rows, uint32 width-px, uint32 height-px, string modes.
func parsePtyReq(payload []byte) (term string, w, h uint32, err error) {
	if len(payload) < 4 {
		return "", 0, 0, fmt.Errorf("payload too short")
	}
	tl := binary.BigEndian.Uint32(payload[:4])
	off := 4 + int(tl)
	if len(payload) < off+16 {
		return "", 0, 0, fmt.Errorf("payload too short for dimensions")
	}
	term = string(payload[4:off])
	w = binary.BigEndian.Uint32(payload[off:])
	h = binary.BigEndian.Uint32(payload[off+4:])
	return term, w, h, nil
}

// parseEnv decodes an env request payload: string name, string value.
func parseEnv(payload []byte) (name, val string, err error) {
	if len(payload) < 4 {
		return "", "", fmt.Errorf("payload too short")
	}
	nl := binary.BigEndian.Uint32(payload[:4])
	off := 4 + int(nl)
	if len(payload) < off+4 {
		return "", "", fmt.Errorf("payload too short for value")
	}
	name = string(payload[4:off])
	vl := binary.BigEndian.Uint32(payload[off : off+4])
	off2 := off + 4 + int(vl)
	if len(payload) < off2 {
		return "", "", fmt.Errorf("payload truncated")
	}
	val = string(payload[off+4 : off2])
	return name, val, nil
}

// parseWindowChange decodes a window-change payload.
func parseWindowChange(payload []byte) (w, h uint32, err error) {
	if len(payload) < 8 {
		return 0, 0, fmt.Errorf("payload too short")
	}
	w = binary.BigEndian.Uint32(payload[:4])
	h = binary.BigEndian.Uint32(payload[4:8])
	return w, h, nil
}
