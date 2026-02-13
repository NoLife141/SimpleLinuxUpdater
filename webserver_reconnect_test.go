package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeSSHSession struct {
	runErr     error
	stdoutText string
	stderrText string
	stdout     io.Writer
	stderr     io.Writer
}

func (s *fakeSSHSession) SetStdin(io.Reader) {}

func (s *fakeSSHSession) SetStdout(w io.Writer) {
	s.stdout = w
}

func (s *fakeSSHSession) SetStderr(w io.Writer) {
	s.stderr = w
}

func (s *fakeSSHSession) Run(string) error {
	if s.stdout != nil && s.stdoutText != "" {
		_, _ = io.WriteString(s.stdout, s.stdoutText)
	}
	if s.stderr != nil && s.stderrText != "" {
		_, _ = io.WriteString(s.stderr, s.stderrText)
	}
	return s.runErr
}

func (s *fakeSSHSession) Close() error { return nil }

type fakeSSHConnection struct {
	sessionFactory  func() sshSessionRunner
	newSessionCalls int
	closed          bool
}

func (c *fakeSSHConnection) NewSession() (sshSessionRunner, error) {
	c.newSessionCalls++
	if c.sessionFactory == nil {
		return nil, errors.New("missing session factory")
	}
	return c.sessionFactory(), nil
}

func (c *fakeSSHConnection) Close() error {
	c.closed = true
	return nil
}

func TestRetryReconnectsSSHConnectionBeforeSecondAttempt(t *testing.T) {
	origDial := dialSSHConnection
	t.Cleanup(func() { dialSSHConnection = origDial })

	firstConn := &fakeSSHConnection{
		sessionFactory: func() sshSessionRunner {
			return &fakeSSHSession{
				runErr:     errors.New("exit status 100"),
				stderrText: "connection reset by peer",
			}
		},
	}
	secondConn := &fakeSSHConnection{
		sessionFactory: func() sshSessionRunner {
			return &fakeSSHSession{}
		},
	}

	dialCalls := 0
	dialSSHConnection = func(_ Server, _ *ssh.ClientConfig) (sshConnection, error) {
		dialCalls++
		if dialCalls == 1 {
			return firstConn, nil
		}
		return secondConn, nil
	}

	server := Server{Name: "srv", Host: "example.org", Port: 22}
	var conn sshConnection
	var err error
	conn, err = dialSSHConnection(server, nil)
	if err != nil {
		t.Fatalf("initial dial failed: %v", err)
	}
	defer conn.Close()

	attempt := 0
	policy := RetryPolicy{
		MaxAttempts: 2,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
		JitterPct:   0,
	}
	var stdout, stderr bytes.Buffer
	err = runWithRetryWithSleep(policy, "test.reconnect", func() error {
		attempt++
		if attempt > 1 {
			if reconnectErr := reconnectSSHClient(server, nil, &conn); reconnectErr != nil {
				return reconnectErr
			}
		}
		session, sessionErr := conn.NewSession()
		if sessionErr != nil {
			return sessionErr
		}
		defer session.Close()
		stdout.Reset()
		stderr.Reset()
		session.SetStdout(&stdout)
		session.SetStderr(&stderr)
		runErr := session.Run("sudo apt update")
		return markRetryableFromOutput(runErr, stdout.String()+"\n"+stderr.String())
	}, nil, func(time.Duration) {})
	if err != nil {
		t.Fatalf("runWithRetryWithSleep returned error: %v", err)
	}

	if dialCalls != 2 {
		t.Fatalf("dial calls = %d, want 2", dialCalls)
	}
	if !firstConn.closed {
		t.Fatalf("expected first connection to be closed before reconnect")
	}
	if firstConn.newSessionCalls != 1 {
		t.Fatalf("first connection sessions = %d, want 1", firstConn.newSessionCalls)
	}
	if secondConn.newSessionCalls != 1 {
		t.Fatalf("second connection sessions = %d, want 1", secondConn.newSessionCalls)
	}
}
