package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func TestProfileResolution(t *testing.T) {
	project := t.TempDir()
	nested := filepath.Join(project, "subdirectory")

	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}

	t.Chdir(nested)
	cmd := &cobra.Command{}
	cmd.Flags().String("profile", "", "")
	check := func(want string) {
		t.Helper()
		got, err := resolveProfile(cmd)

		if err != nil || got != want {
			t.Fatalf("profile: got %q, want %q: %v", got, want, err)
		}
	}
	check("subdirectory")
	parentConfig := filepath.Join(project, profileConfigName)

	if err := os.WriteFile(parentConfig, []byte(`{"profile":"parent-profile"}`), 0600); err != nil {
		t.Fatal(err)
	}

	check("parent-profile")
	localConfig := filepath.Join(nested, profileConfigName)

	if err := os.WriteFile(localConfig, []byte(`{"profile":"nearest-profile"}`), 0600); err != nil {
		t.Fatal(err)
	}

	check("nearest-profile")

	if err := cmd.Flags().Set("profile", "explicit"); err != nil {
		t.Fatal(err)
	}

	check("explicit")

	if err := os.WriteFile(localConfig, []byte(`invalid json`), 0600); err != nil {
		t.Fatal(err)
	}

	check("explicit") // Overrides can bypass broken project config.
	cmd.Flags().Lookup("profile").Changed = false

	if _, err := resolveProfile(cmd); err == nil {
		t.Fatal("silently ignored invalid nearest config")
	}

	for _, data := range []string{`null`, `{}`, `{"profile":""}`, `{"profile":"\n"}`, `{"profile":"x","unknown":1}`, `{"profile":"x"} {}`} {
		if err := os.WriteFile(localConfig, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveProfile(cmd); err == nil {
			t.Fatalf("accepted invalid config: %s", data)
		}
	}

	if err := os.Remove(localConfig); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(parentConfig, localConfig); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveProfile(cmd); err == nil {
		t.Fatal("accepted symlink config")
	}
}

func TestProjectProfileCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "project")

	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)
	originalPassword, originalSecret := readPassword, readSecretValue
	secret := "8080"
	readSecretValue = func() ([]byte, error) { return []byte(secret), nil }
	readPassword = func(string) (string, error) { return "pw", nil }
	flag := rootCmd.PersistentFlags().Lookup("profile")
	originalValue, originalChanged := flag.Value.String(), flag.Changed
	defer func() {
		readPassword = originalPassword
		readSecretValue = originalSecret
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		_ = flag.Value.Set(originalValue)
		flag.Changed = originalChanged
	}()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error {
		t.Helper()
		_ = flag.Value.Set("")
		flag.Changed = false
		out.Reset()
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}

	if err := run("profile", "use"); err != nil {
		t.Fatal(err)
	}

	created, err := readProfileConfig(filepath.Join(project, profileConfigName))

	if err != nil || created.Profile != "project" {
		t.Fatalf("folder default: %v %v", created, err)
	}

	if err := run("profile", "use", "node-app"); err != nil {
		t.Fatal(err)
	}

	config, err := readProfileConfig(filepath.Join(project, profileConfigName))

	if err != nil || config.Profile != "node-app" {
		t.Fatalf("saved config: %v %v", config, err)
	}

	before, err := os.ReadFile(filepath.Join(project, profileConfigName))

	if err != nil {
		t.Fatal(err)
	}

	if err := run("profile", "use"); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(filepath.Join(project, profileConfigName))

	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("reuse modified existing config")
	}

	nested := filepath.Join(project, "nested")

	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}

	if err := run("profile", "use"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(out.Bytes(), []byte(`Using profile "node-app"`)) {
		t.Fatalf("wrong inherited profile: %s", out.String())
	}

	if _, err := os.Stat(filepath.Join(nested, profileConfigName)); !os.IsNotExist(err) {
		t.Fatal("reuse created a shadow config")
	}

	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(store.GetVaultFilePath()); !os.IsNotExist(err) {
		t.Fatal("profile use created a vault")
	}

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	if err := run("set", "PORT"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "PORT"); err != nil || out.String() != "8080\n" {
		t.Fatalf("get: %q %v", out.String(), err)
	}

	secret = "9090"

	if err := run("set", "PORT"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "PORT"); err != nil || out.String() != "9090\n" {
		t.Fatalf("update: %q %v", out.String(), err)
	}

	secret = "1234"

	if err := run("--profile", "override", "set", "PORT"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "--profile", "override", "PORT"); err != nil || out.String() != "1234\n" {
		t.Fatalf("explicit profile: %q %v", out.String(), err)
	}

	secret = "5678"

	if err := run("set", "legacy", "PORT"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "legacy", "PORT"); err != nil || out.String() != "5678\n" {
		t.Fatalf("legacy: %q %v", out.String(), err)
	}

	for _, args := range [][]string{
		{"--profile", "", "get", "PORT"}, {"--profile", "override", "get", "legacy", "PORT"},
		{"--profile", "override", "profile", "use", "node-app"}, {"profile", "use", ""},
		{"--profile", "override", "profile", "use"}, {"profile", "use", "one", "two"},
	} {
		if err := run(args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}

	config, err = readProfileConfig(filepath.Join(project, profileConfigName))

	if err != nil || config.Profile != "node-app" {
		t.Fatalf("override persisted unexpectedly: %v %v", config, err)
	}

	if err := run("profile", "use", "second"); err != nil {
		t.Fatal(err)
	}

	config, err = readProfileConfig(filepath.Join(project, profileConfigName))

	if err != nil || config.Profile != "second" {
		t.Fatalf("switch default: %v %v", config, err)
	}

	path := filepath.Join(project, profileConfigName)

	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := run("profile", "use"); err == nil {
		t.Fatal("silently accepted broken config")
	}

	if err := run("profile", "use", "third"); err == nil {
		t.Fatal("overwrote broken config")
	}

	data, _ := os.ReadFile(path)

	if string(data) != "broken" {
		t.Fatal("changed broken config")
	}

	if err := run("--profile", "override", "get", "PORT"); err != nil || out.String() != "1234\n" {
		t.Fatalf("override broken config: %q %v", out.String(), err)
	}
}
