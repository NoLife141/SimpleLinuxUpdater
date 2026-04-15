package main

import "golang.org/x/crypto/ssh"

func setDialSSHConnection(fn func(Server, *ssh.ClientConfig) (sshConnection, error)) {
	dialSSHConnectionMu.Lock()
	defer dialSSHConnectionMu.Unlock()
	dialSSHConnection = fn
}
