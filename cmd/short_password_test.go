package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"strings"
	"testing"
)

func TestInitShortPasswordConfirmation(t *testing.T) {
	originalPassword, originalConfirmation := readPassword, readConfirmation
	defer func() {
		readPassword, readConfirmation = originalPassword, originalConfirmation
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()

	for _, tc := range []struct {
		name, password, confirmation, answer string
		wantErr                              bool
	}{
		{"yes", "pw", "pw", "y\n", false},
		{"no", "pw", "pw", "n\n", true},
		{"enter", "pw", "pw", "\n", true},
		{"eof", "pw", "pw", "", true},
		{"retry", "pw", "pw", "maybe\ny\n", false},
		{"mismatch", "pw", "different", "y\n", true},
		{"empty", "", "", "y\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			passwords := []string{tc.password, tc.confirmation}
			readPassword = func(string) (string, error) { p := passwords[0]; passwords = passwords[1:]; return p, nil }
			var output bytes.Buffer
			rootCmd.SetOut(&output)
			rootCmd.SetErr(&output)
			readConfirmation = func(prompt string) (bool, error) { return readYesNo(strings.NewReader(tc.answer), &output, prompt) }
			rootCmd.SetArgs([]string{"init"})
			err := rootCmd.Execute()

			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected result: %v", err)
			}

			if tc.wantErr {
				if _, err := os.Stat(store.GetVaultFilePath()); !os.IsNotExist(err) {
					t.Fatal("canceled initialization created vault")
				}
			} else if _, err := store.Load(tc.password); err != nil {
				t.Fatal("confirmed short password cannot unlock", err)
			}
		})
	}
}

func TestMigrateShortPasswordConfirmation(t *testing.T) {
	originalPassword, originalConfirmation := readPassword, readConfirmation
	flag := migrateCmd.Flags().Lookup("new-password")
	originalFlag, originalChanged := flag.Value.String(), flag.Changed
	defer func() {
		readPassword, readConfirmation = originalPassword, originalConfirmation
		flag.Value.Set(originalFlag)
		flag.Changed = originalChanged
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()

	for _, rotate := range []bool{false, true} {
		for _, accept := range []bool{false, true} {
			name := "keep"
			if rotate {
				name = "rotate"
			}
			if accept {
				name += "-yes"
			} else {
				name += "-no"
			}
			t.Run(name, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				old := "pw"

				if rotate {
					old = "a long original password"
				}

				if err := store.Initialize(old); err != nil {
					t.Fatal(err)
				}

				if err := store.Update(old, "app", "KEY", "preserve-me"); err != nil {
					t.Fatal(err)
				}

				before, _ := os.ReadFile(store.GetVaultFilePath())
				backupBefore, _ := os.ReadFile(store.BackupFilePath())
				passwords := []string{old, "pw", "pw"}
				readPassword = func(string) (string, error) { p := passwords[0]; passwords = passwords[1:]; return p, nil }
				var output bytes.Buffer
				rootCmd.SetOut(&output)
				rootCmd.SetErr(&output)
				calls := 0
				readConfirmation = func(prompt string) (bool, error) {
					calls++
					answer := "n\n"

					if accept {
						answer = "y\n"
					}

					return readYesNo(strings.NewReader(answer), &output, prompt)
				}
				flag.Value.Set("false")
				flag.Changed = false
				args := []string{"migrate"}

				if rotate {
					args = append(args, "--new-password")
				}

				rootCmd.SetArgs(args)
				err := rootCmd.Execute()

				if (err == nil) != accept || calls != 1 {
					t.Fatalf("err=%v confirmations=%d", err, calls)
				}

				if accept {
					s, err := store.Load("pw")
					if err != nil || s["app"]["KEY"] != "preserve-me" {
						t.Fatal("confirmed migration failed", err)
					}
				} else {
					after, _ := os.ReadFile(store.GetVaultFilePath())
					backupAfter, _ := os.ReadFile(store.BackupFilePath())
					if !bytes.Equal(before, after) || !bytes.Equal(backupBefore, backupAfter) {
						t.Fatal("declined migration changed a snapshot")
					}
				}
			})
		}
	}
}
