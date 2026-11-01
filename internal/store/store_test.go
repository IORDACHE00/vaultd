package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestInitializeAndUpdate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := Load("pw"); !os.IsNotExist(err) {
		t.Fatalf("missing vault: %v", err)
	}

	if err := Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadFile(GetVaultFilePath())
	if err := Initialize("other"); err == nil {
		t.Fatal("reinitialization succeeded")
	}

	after, _ := os.ReadFile(GetVaultFilePath())
	if string(before) != string(after) {
		t.Fatal("init changed existing vault")
	}

	if err := Update("wrong", "app", "KEY", "lost"); err == nil {
		t.Fatal("accepted wrong password")
	}

	if err := Update("pw", "app", "bad-key", "x"); err == nil {
		t.Fatal("accepted invalid key")
	}

	if err := Update("pw", "app", "KEY", "value='\n$()"); err != nil {
		t.Fatal(err)
	}

	s, err := Load("pw")
	if err != nil || s["app"]["KEY"] != "value='\n$()" {
		t.Fatalf("roundtrip: %v %v", s, err)
	}

	for path, want := range map[string]os.FileMode{GetVaultFilePath(): 0600, filepath.Dir(GetVaultFilePath()): 0700} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if info.Mode().Perm() != want {
			t.Fatalf("%s: permissions %o", path, info.Mode().Perm())
		}
	}

	files, _ := filepath.Glob(filepath.Join(filepath.Dir(GetVaultFilePath()), ".secrets-*"))

	if len(files) != 0 {
		t.Fatalf("leaked temporary files: %v", files)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			if err := Update("pw", "app", fmt.Sprintf("KEY_%d", i), "value"); err != nil {
				t.Error(err)
			}
		}(i)
	}

	wg.Wait()

	s, err := Load("pw")
	if err != nil {
		t.Fatal(err)
	}

	if len(s["app"]) != 8 {
		t.Fatalf("lost updates: %v", s)
	}
}

func TestCorruptVaultNotOverwritten(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, err := Directory(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(GetVaultFilePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Update("pw", "app", "KEY", "value"); err == nil {
		t.Fatal("overwrote corrupt vault")
	}

	if err := Initialize("pw"); err == nil {
		t.Fatal("overwrote corrupt vault")
	}

	data, _ := os.ReadFile(GetVaultFilePath())
	if string(data) != "corrupt" {
		t.Fatal("corrupt file changed")
	}
}
