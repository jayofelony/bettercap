package ssh_proxy

import (
	"github.com/bettercap/bettercap/v2/log"
	"github.com/bettercap/bettercap/v2/session"

	"github.com/evilsocket/islazy/plugin"

	"github.com/robertkrimen/otto"
)

// SSHProxyScript wraps a JS plugin for the ssh.proxy module.
//
// The script may define:
//
//	function onSSHData(sessionID, direction, data) { ... return data; }
//
// sessionID: string like "1.2.3.4:12345->5.6.7.8:22[session]"
// direction: "client->server" or "server->client"
// data:      byte array
// return:    modified byte array, or null/undefined to keep original
type SSHProxyScript struct {
	*plugin.Plugin
	hasOnData bool
}

func LoadSSHProxyScript(path string, sess *session.Session) (err error, s *SSHProxyScript) {
	log.Info("loading ssh proxy script %s ...", path)

	plug, err := plugin.Load(path)
	if err != nil {
		return
	}

	if err = plug.Set("env", sess.Env.Data); err != nil {
		log.Error("error while defining environment: %+v", err)
		return
	}

	if plug.HasFunc("onLoad") {
		if _, err = plug.Call("onLoad"); err != nil {
			log.Error("error executing onLoad: %s", "\ntraceback:\n  "+err.(*otto.Error).String())
			return
		}
	}

	s = &SSHProxyScript{
		Plugin:    plug,
		hasOnData: plug.HasFunc("onSSHData"),
	}
	return
}

// OnData invokes the JS onSSHData callback if defined.
// Returns nil if the script did not modify the data.
func (s *SSHProxyScript) OnData(sessionID, direction string, data []byte) []byte {
	if !s.hasOnData {
		return nil
	}

	ret, err := s.Call("onSSHData", sessionID, direction, data)
	if err != nil {
		log.Error("error in onSSHData: %v", err)
		return nil
	}

	if ret == nil {
		return nil
	}

	// Convert otto return value to []byte
	switch v := ret.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}
