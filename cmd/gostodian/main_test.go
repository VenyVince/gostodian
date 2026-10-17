package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gostodian/internal/config"
	"gostodian/internal/ssh"
	"gostodian/internal/vpn"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "gostodian") {
		t.Fatalf("output = %q", got)
	}
}

func TestConfigValidateExample(t *testing.T) {
	example := filepath.Join("..", "..", "config", "config.yaml.example")
	var out bytes.Buffer
	if err := run([]string{"config", "validate", "--config", example}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "config ok") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestConfigValidateMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("server:\n  host: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"config", "validate", "--config", path}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, errUsage) {
		t.Fatalf("got usage, want validate error: %v", err)
	}
}

func TestUnknownCommand(t *testing.T) {
	var stderr bytes.Buffer
	err := run([]string{"nope"}, io.Discard, &stderr)
	if !errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoArgs(t *testing.T) {
	err := run(nil, io.Discard, io.Discard)
	if !errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
}

func TestExecIsUsageError(t *testing.T) {
	restoreConnect(t)
	called := false
	connect = func(config.Config) runner {
		called = true
		return stubRunner{}
	}

	var stderr bytes.Buffer
	err := run([]string{"exec"}, io.Discard, &stderr)
	if !errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Fatal("exec still connected")
	}
	if !strings.Contains(stderr.String(), "gostodian run") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRejectsExtraArgs(t *testing.T) {
	restoreConnect(t)
	called := false
	connect = func(config.Config) runner {
		called = true
		return stubRunner{}
	}

	var stderr bytes.Buffer
	err := run([]string{"run", "reboot"}, io.Discard, &stderr)
	if !errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Fatal("extra args still connected")
	}
	if !strings.Contains(stderr.String(), "usage: gostodian run") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCallsSSH(t *testing.T) {
	restoreConnect(t)
	var gotCfg config.Config
	connect = func(cfg config.Config) runner {
		gotCfg = cfg
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{Stdout: "ok\n", Stderr: "warn\n"}, nil
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "--config", example, "--log-dir", logDir}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if gotCfg.Server.User != "gostodian" {
		t.Fatalf("user = %q", gotCfg.Server.User)
	}
	if stdout.String() != "ok\n" || !strings.Contains(stderr.String(), "warn\n") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "execution_id:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	history := readHistory(t, logDir)
	if history.Status != "ok" || len(history.Steps) != 1 || history.Steps[0].Step != "run" || history.Steps[0].Command != ssh.AgentPath {
		t.Fatalf("history = %+v", history)
	}
	if strings.Contains(historyText(t, logDir), "id_ed25519") {
		t.Fatal("identity path was written to the log")
	}
}

func TestRunRemoteExit(t *testing.T) {
	restoreConnect(t)
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{Stdout: "no\n", ExitCode: 1}, nil
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	var stdout bytes.Buffer
	err := run([]string{"run", "--config", example, "--log-dir", t.TempDir()}, &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("err = %v", err)
	}
	if stdout.String() != "no\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunReturnsDialError(t *testing.T) {
	restoreConnect(t)
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{}, ssh.ErrAuthFailed
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	err := run([]string{"run", "--config", example, "--log-dir", logDir}, io.Discard, io.Discard)
	if !errors.Is(err, ssh.ErrAuthFailed) {
		t.Fatalf("err = %v", err)
	}
	history := readHistory(t, logDir)
	if history.Status != "failed" || len(history.Steps) != 1 || history.Steps[0].Class != "auth_failed" {
		t.Fatalf("history = %+v", history)
	}
}

func TestRunHostKeyMismatchClass(t *testing.T) {
	restoreConnect(t)
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{}, ssh.ErrHostKeyMismatch
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	err := run([]string{"run", "--config", example, "--log-dir", logDir}, io.Discard, io.Discard)
	if !errors.Is(err, ssh.ErrHostKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
	history := readHistory(t, logDir)
	if history.Status != "failed" || len(history.Steps) != 1 || history.Steps[0].Class != "host_key_mismatch" {
		t.Fatalf("history = %+v", history)
	}
}

func TestRunHostUnreachableClass(t *testing.T) {
	restoreConnect(t)
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{}, ssh.ErrHostUnreachable
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	err := run([]string{"run", "--config", example, "--log-dir", logDir}, io.Discard, io.Discard)
	if !errors.Is(err, ssh.ErrHostUnreachable) {
		t.Fatalf("err = %v", err)
	}
	history := readHistory(t, logDir)
	if history.Status != "failed" || len(history.Steps) != 1 || history.Steps[0].Class != "host_unreachable" {
		t.Fatalf("history = %+v", history)
	}
}

func TestRunVPNDownSkipsSSH(t *testing.T) {
	restoreConnect(t)
	restoreRequireVPN(t)
	called := false
	connect = func(config.Config) runner {
		called = true
		return stubRunner{}
	}
	requireVPN = func(name string) error {
		if name != "wg0" {
			t.Fatalf("interface = %q", name)
		}
		return vpn.ErrRequired
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := "server:\n  host: homelab.example\n  user: gostodian\nssh:\n  identity_file: secrets/id_ed25519\n  known_hosts_file: secrets/known_hosts\nvpn:\n  interface: wg0\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	logDir := t.TempDir()
	err := run([]string{"run", "--config", cfgPath, "--log-dir", logDir}, io.Discard, io.Discard)
	if !errors.Is(err, vpn.ErrRequired) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Fatal("vpn down still dialed")
	}
	history := readHistory(t, logDir)
	if history.Status != "failed" || len(history.Steps) != 1 || history.Steps[0].Class != "vpn_required" {
		t.Fatalf("history = %+v", history)
	}
}

func TestRunEmptyVPNDials(t *testing.T) {
	restoreConnect(t)
	restoreRequireVPN(t)
	called := false
	connect = func(config.Config) runner {
		called = true
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{Stdout: "ok\n"}, nil
			},
		}
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := "server:\n  host: homelab.example\n  user: gostodian\nssh:\n  identity_file: secrets/id_ed25519\n  known_hosts_file: secrets/known_hosts\nvpn:\n  interface: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"run", "--config", cfgPath, "--log-dir", t.TempDir()}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("empty vpn interface skipped the dial")
	}
}

func TestRunFailureLogOmitsPrivateKey(t *testing.T) {
	restoreConnect(t)
	const secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETMATERIAL\n-----END OPENSSH PRIVATE KEY-----"
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{Stderr: secret}, errors.New(secret)
			},
		}
	}

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	var stderr bytes.Buffer
	err := run([]string{"run", "--config", example, "--log-dir", logDir}, io.Discard, &stderr)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(stderr.String(), "SECRETMATERIAL") || strings.Contains(stderr.String(), "PRIVATE KEY") {
		t.Fatalf("stderr leaked key: %q", stderr.String())
	}
	logged := historyText(t, logDir)
	if strings.Contains(logged, "SECRETMATERIAL") || strings.Contains(logged, "PRIVATE KEY") {
		t.Fatalf("history leaked key: %s", logged)
	}
	if !strings.Contains(logged, "[redacted]") {
		t.Fatalf("history = %s", logged)
	}
}

func TestRunDoesNotReadOtherSecrets(t *testing.T) {
	restoreConnect(t)
	connect = func(config.Config) runner {
		return stubRunner{
			run: func() (ssh.Result, error) {
				return ssh.Result{Stdout: "ok\n"}, nil
			},
		}
	}

	dir := t.TempDir()
	const webhook = "https://discord.example/api/webhooks/secret-token"
	for _, name := range []string{"ai", "s3-access", "hook"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(webhook), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOSTODIAN_AI_API_KEY_FILE", filepath.Join(dir, "ai"))
	t.Setenv("GOSTODIAN_S3_ACCESS_KEY_FILE", filepath.Join(dir, "s3-access"))
	t.Setenv("GOSTODIAN_S3_SECRET_KEY_FILE", filepath.Join(dir, "missing-s3-secret"))
	t.Setenv("GOSTODIAN_DISCORD_WEBHOOK_FILE", filepath.Join(dir, "hook"))

	example := filepath.Join("..", "..", "config", "config.yaml.example")
	logDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"run", "--config", example, "--log-dir", logDir}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	blob := stdout.String() + stderr.String() + historyText(t, logDir)
	if strings.Contains(blob, "secret-token") || strings.Contains(blob, "discord.example") {
		t.Fatalf("unread secret appeared: %s", blob)
	}
}

type historyFile struct {
	Status string `json:"status"`
	Steps  []struct {
		Step    string `json:"step"`
		Command string `json:"command"`
		Class   string `json:"class"`
	} `json:"steps"`
}

func readHistory(t *testing.T, dir string) historyFile {
	t.Helper()
	var history historyFile
	if err := json.Unmarshal(readSuffix(t, dir, ".json"), &history); err != nil {
		t.Fatal(err)
	}
	return history
}

func historyText(t *testing.T, dir string) string {
	t.Helper()
	return string(readSuffix(t, dir, ".jsonl")) + string(readSuffix(t, dir, ".json"))
}

func readSuffix(t *testing.T, dir, suffix string) []byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if suffix == ".json" && strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Fatalf("no %s file in %s", suffix, dir)
	return nil
}

type stubRunner struct {
	run func() (ssh.Result, error)
}

func (s stubRunner) Run() (ssh.Result, error) {
	if s.run == nil {
		return ssh.Result{}, nil
	}
	return s.run()
}

func restoreConnect(t *testing.T) {
	t.Helper()
	prev := connect
	t.Cleanup(func() { connect = prev })
}

func restoreRequireVPN(t *testing.T) {
	t.Helper()
	prev := requireVPN
	t.Cleanup(func() { requireVPN = prev })
}
