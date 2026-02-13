package main

import (
	"errors"
	"testing"
	"time"
)

func TestLoadRetryPolicyFromEnvDefaults(t *testing.T) {
	t.Setenv(retryMaxAttemptsEnv, "")
	t.Setenv(retryBaseDelayMSEnv, "")
	t.Setenv(retryMaxDelayMSEnv, "")
	t.Setenv(retryJitterPctEnv, "")

	p := loadRetryPolicyFromEnv()
	if p.MaxAttempts != 3 {
		t.Fatalf("MaxAttempts = %d, want 3", p.MaxAttempts)
	}
	if p.BaseDelay != time.Second {
		t.Fatalf("BaseDelay = %v, want 1s", p.BaseDelay)
	}
	if p.MaxDelay != 8*time.Second {
		t.Fatalf("MaxDelay = %v, want 8s", p.MaxDelay)
	}
	if p.JitterPct != 20 {
		t.Fatalf("JitterPct = %d, want 20", p.JitterPct)
	}
}

func TestLoadRetryPolicyFromEnvOverrideAndInvalidFallback(t *testing.T) {
	t.Setenv(retryMaxAttemptsEnv, "5")
	t.Setenv(retryBaseDelayMSEnv, "250")
	t.Setenv(retryMaxDelayMSEnv, "2000")
	t.Setenv(retryJitterPctEnv, "15")
	p := loadRetryPolicyFromEnv()
	if p.MaxAttempts != 5 || p.BaseDelay != 250*time.Millisecond || p.MaxDelay != 2*time.Second || p.JitterPct != 15 {
		t.Fatalf("unexpected override policy: %+v", p)
	}

	t.Setenv(retryMaxAttemptsEnv, "0")
	t.Setenv(retryBaseDelayMSEnv, "-1")
	t.Setenv(retryMaxDelayMSEnv, "-1")
	t.Setenv(retryJitterPctEnv, "999")
	p = loadRetryPolicyFromEnv()
	if p.MaxAttempts != 3 || p.BaseDelay != time.Second || p.MaxDelay != 8*time.Second || p.JitterPct != 20 {
		t.Fatalf("invalid env should fallback to defaults, got %+v", p)
	}
}

func TestIsRetryableError(t *testing.T) {
	retryable := []error{
		errors.New("dial tcp: connection refused"),
		errors.New("read: connection reset by peer"),
		errors.New("i/o timeout"),
		errors.New("E: Could not get lock /var/lib/dpkg/lock-frontend"),
	}
	for _, err := range retryable {
		if !isRetryableError(err) {
			t.Fatalf("isRetryableError(%q) = false, want true", err.Error())
		}
	}

	nonRetryable := []error{
		errors.New("ssh: handshake failed: unable to authenticate"),
		errors.New("host key verification failed"),
		errors.New("missing password or SSH key"),
	}
	for _, err := range nonRetryable {
		if isRetryableError(err) {
			t.Fatalf("isRetryableError(%q) = true, want false", err.Error())
		}
	}
}

func TestMarkRetryableFromOutputTagsGenericExitError(t *testing.T) {
	err := errors.New("Process exited with status 100")
	tagged := markRetryableFromOutput(err, "E: Could not get lock /var/lib/dpkg/lock-frontend")
	if !isRetryableError(tagged) {
		t.Fatalf("tagged error should be retryable, got: %v", tagged)
	}
}

func TestRunWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	p := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		JitterPct:   0,
	}
	attempts := 0
	retryCalls := 0
	err := runWithRetryWithSleep(p, "test.op", func() error {
		attempts++
		if attempts < 2 {
			return errors.New("connection reset by peer")
		}
		return nil
	}, func(_ int, _ time.Duration, _ error) {
		retryCalls++
	}, func(_ time.Duration) {})
	if err != nil {
		t.Fatalf("runWithRetryWithSleep() error = %v, want nil", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if retryCalls != 1 {
		t.Fatalf("retryCalls = %d, want 1", retryCalls)
	}
}

func TestRunWithRetryStopsOnPermanentError(t *testing.T) {
	p := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		JitterPct:   0,
	}
	attempts := 0
	retryCalls := 0
	err := runWithRetryWithSleep(p, "test.op", func() error {
		attempts++
		return errors.New("unable to authenticate")
	}, func(_ int, _ time.Duration, _ error) {
		retryCalls++
	}, func(_ time.Duration) {})
	if err == nil {
		t.Fatalf("runWithRetryWithSleep() error = nil, want non-nil")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if retryCalls != 0 {
		t.Fatalf("retryCalls = %d, want 0", retryCalls)
	}
}

func TestRunWithRetryExhaustsAttemptsOnTransientError(t *testing.T) {
	p := RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		JitterPct:   0,
	}
	attempts := 0
	retryCalls := 0
	var waits []time.Duration
	err := runWithRetryWithSleep(p, "test.op", func() error {
		attempts++
		return errors.New("connection refused")
	}, func(_ int, wait time.Duration, _ error) {
		retryCalls++
		waits = append(waits, wait)
	}, func(_ time.Duration) {})
	if err == nil {
		t.Fatalf("runWithRetryWithSleep() error = nil, want non-nil")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if retryCalls != 2 {
		t.Fatalf("retryCalls = %d, want 2", retryCalls)
	}
	if len(waits) != 2 || waits[0] != 10*time.Millisecond || waits[1] != 20*time.Millisecond {
		t.Fatalf("unexpected waits: %v", waits)
	}
}
