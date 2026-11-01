package cmd

import (
	"bytes"
	"context"
	"errors"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Run in a subprocess because the real command replaces its process with exec.
func TestRunProcessHelper(t *testing.T) {
	if os.Getenv("VAULTD_RUN_TEST_HELPER") != "1" {
		return
	}

	for i, arg := range os.Args {
		if arg == "--" {
			rootCmd.SetArgs(os.Args[i+1:])
			Execute()
			os.Exit(0)
		}
	}

	os.Exit(99)
}

func TestRunCommand(t *testing.T) {
	home, err := os.MkdirTemp("", "vd-")

	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(home)
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")

	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	literal := "spaces 'quotes'\n$(not-executed) `literal`"

	for key, value := range map[string]string{"PORT": "8080", "VD_LITERAL": literal, "VD_EMPTY": ""} {
		if err := store.Update("pw", "project", key, value); err != nil {
			t.Fatal(err)
		}
	}

	if err := store.Update("pw", "other", "PORT", "9000"); err != nil {
		t.Fatal(err)
	}

	l, err := ipc.Listen()

	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx, l, "pw") }()
	run := func(args ...string) (string, string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		argv := append([]string{"-test.run=^TestRunProcessHelper$", "--", "run"}, args...)
		child := exec.CommandContext(ctx, os.Args[0], argv...)
		child.Dir = project
		child.Env = append(os.Environ(), "VAULTD_RUN_TEST_HELPER=1", "PORT=parent", "VD_KEEP=inherited", "VD_EMPTY=parent")
		var stdout, stderr bytes.Buffer
		child.Stdout, child.Stderr = &stdout, &stderr
		err := child.Run()
		return stdout.String(), stderr.String(), err
	}
	out, stderr, err := run("--", "/bin/sh", "-c", `printf '%s|%s|%s|%s|%s' "$PORT" "$VD_KEEP" "$VD_EMPTY" "$VD_LITERAL" "$1"`, "sh", "argument with spaces")

	if want := "8080|inherited||" + literal + "|argument with spaces"; err != nil || out != want || stderr != "" {
		t.Fatalf("run: stdout=%q stderr=%q err=%v", out, stderr, err)
	}

	out, stderr, err = run("--app", "other", "--", "/bin/sh", "-c", `printf '%s' "$PORT"`)

	if err != nil || out != "9000" {
		t.Fatalf("explicit profile: %q %q %v", out, stderr, err)
	}

	if err := os.WriteFile(filepath.Join(project, profileConfigName), []byte(`{"profile":"other"}`), 0600); err != nil {
		t.Fatal(err)
	}

	out, stderr, err = run("--", "/bin/sh", "-c", `printf '%s' "$PORT"`)

	if err != nil || out != "9000" {
		t.Fatalf("project profile: %q %q %v", out, stderr, err)
	}

	out, stderr, err = run("--profile", "project", "--", "/bin/sh", "-c", `printf '%s' "$PORT"`)

	if err != nil || out != "8080" {
		t.Fatalf("profile override: %q %q %v", out, stderr, err)
	}

	_, _, err = run("--", "/bin/sh", "-c", "exit 23")
	var exit *exec.ExitError

	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("exit code: %v", err)
	}

	_, _, err = run("--", "/bin/sh", "-c", "kill -TERM $$")

	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("signal: %v", err)
	}

	for _, args := range [][]string{
		{}, {"/bin/echo", "missing separator"}, {"--", ""},
		{"--app", "missing", "--", "/bin/echo", "must not execute"},
		{"--app=", "--", "/bin/echo", "must not execute"},
		{"--profile=", "--", "/bin/echo", "must not execute"},
		{"--profile", "project", "--app", "other", "--", "/bin/echo", "must not execute"},
		{"--", "vaultd-command-that-does-not-exist"},
	} {
		out, _, err := run(args...)
		if err == nil || out != "" {
			t.Fatalf("invalid run %v: %q %v", args, out, err)
		}
	}

	if err := ipc.Stop(); err != nil {
		t.Fatal(err)
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	out, _, err = run("--", "/bin/echo", "must not execute")

	if err == nil || out != "" {
		t.Fatalf("missing daemon: %q %v", out, err)
	}
}

func TestRunEnvironment(t *testing.T) {
	inherited := []string{"PORT=old", "KEEP=unchanged", "EMPTY=old"}
	env, err := mergeEnvironment(inherited, map[string]string{"PORT": "8080", "EMPTY": ""})

	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(env, "\n"); got != "EMPTY=\nKEEP=unchanged\nPORT=8080" {
		t.Fatal(got)
	}

	if inherited[0] != "PORT=old" {
		t.Fatal("modified inherited environment")
	}

	for _, secrets := range []map[string]string{{"BAD-KEY": "x"}, {"KEY": "nul\x00value"}} {
		if _, err := mergeEnvironment(nil, secrets); err == nil {
			t.Fatal("invalid secret accepted")
		}
	}

	dir := t.TempDir()
	command := filepath.Join(dir, "my-command")

	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}

	if got, err := environmentExecutable("my-command", []string{"PATH=" + dir}); err != nil || got != command {
		t.Fatalf("injected PATH: %q %v", got, err)
	}

	if _, err := environmentExecutable("sh", nil); err == nil {
		t.Fatal("used parent PATH instead of child PATH")
	}
}
