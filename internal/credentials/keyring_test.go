package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IORDACHE00/vaultd/internal/store"
)

type fakeBackend struct {
	items                     map[string]string
	getCalls, setCalls        int
	getErr, setErr, deleteErr error
}

func (f *fakeBackend) Set(s, a, p string) error {
	f.setCalls++

	if f.setErr != nil {
		return f.setErr
	}

	if f.items == nil {
		f.items = make(map[string]string)
	}

	f.items[s+"/"+a] = p

	return nil
}

func (f *fakeBackend) Get(s, a string) (string, error) {
	f.getCalls++

	if f.getErr != nil {
		return "", f.getErr
	}

	p, ok := f.items[s+"/"+a]
	if !ok {
		return "", errors.New("missing credential")
	}

	return p, nil
}

func (f *fakeBackend) Delete(s, a string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}

	delete(f.items, s+"/"+a)

	return nil
}

func TestKeyringOptInLifecycle(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	f := &fakeBackend{}
	m := Manager{Backend: f}

	if p, on, err := m.Password(); err != nil || on || p != "" || f.getCalls != 0 {
		t.Fatalf("default queried keyring: %q %v %v", p, on, err)
	}

	if err := store.Initialize("test-password"); err != nil {
		t.Fatal(err)
	}

	if err := m.Enable("wrong"); err == nil || f.setCalls != 0 {
		t.Fatal("enrolled wrong password")
	}

	if err := m.Enable("test-password"); err != nil {
		t.Fatal(err)
	}

	if p, on, err := m.Password(); err != nil || !on || p != "test-password" {
		t.Fatalf("lookup: %q %v %v", p, on, err)
	}

	path, _ := markerPath()
	if path != filepath.Join(os.Getenv("HOME"), ".vaultd", "keyring.enabled") {
		t.Fatalf("unexpected keyring marker path: %s", path)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "test-password") {
		t.Fatal("plaintext password in marker")
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("marker permissions: %v", err)
	}

	f.getErr = errors.New("locked/unavailable")
	if _, on, err := m.Password(); err == nil || !on {
		t.Fatal("silently fell back on lookup failure")
	}

	f.getErr = nil
	f.deleteErr = errors.New("service unavailable")

	if err := m.Disable(); err == nil {
		t.Fatal("pretended credential deletion succeeded")
	}

	if on, err := m.Enabled(); err != nil || !on {
		t.Fatal("removed marker after failed deletion")
	}

	f.deleteErr = nil
	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}

	if on, err := m.Enabled(); err != nil || on || len(f.items) != 0 {
		t.Fatal("disable did not remove credential")
	}

	if err := m.Disable(); err != nil {
		t.Fatal("disable not idempotent")
	}
}

func TestKeyringEnrollmentFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	for _, f := range []*fakeBackend{
		{setErr: errors.New("unavailable")},
		{getErr: errors.New("verification failure")},
	} {
		m := Manager{Backend: f}
		if err := m.Enable("pw"); err == nil {
			t.Fatal("enrollment failure ignored")
		}
		if on, err := m.Enabled(); err != nil || on {
			t.Fatal("enabled marker after failed enrollment")
		}
	}
}

func TestKeyringIdentityAndMarkerValidation(t *testing.T) {
	first := t.TempDir()
	t.Setenv("HOME", first)

	a, err := account()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())

	b, err := account()
	if err != nil || a == b {
		t.Fatal("different vault paths share credential identity")
	}

	t.Setenv("HOME", first)

	m := Manager{Backend: &fakeBackend{}}
	path, _ := markerPath()
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Enabled(); err == nil {
		t.Fatal("accepted corrupt marker")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(first, "marker-target")
	if err := os.WriteFile(target, []byte(markerContents), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Enabled(); err == nil {
		t.Fatal("accepted symlink marker")
	}
}
