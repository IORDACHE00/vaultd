package cmd

import (
	"bytes"
	"errors"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"io"
	"strings"
	"testing"
)

func TestYesNoConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, input   string
		want, wantErr bool
	}{
		{"yes", "y\n", true, false},
		{"uppercase", " Y \r\n", true, false},
		{"no", "n\n", false, false},
		{"default-no", "\n", false, false},
		{"invalid-retry", "maybe\ny\n", true, false},
		{"invalid-then-no", "yes\nN\n", false, false},
		{"eof", "", false, true},
		{"incomplete-yes", "y", false, true},
		{"overlong", strings.Repeat("y", 129) + "\ny\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			got, err := readYesNo(strings.NewReader(tc.input), &output, "Continue? [y/N]: ")

			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("got %v, %v", got, err)
			}

			if !strings.Contains(output.String(), "[y/N]") {
				t.Fatal("missing default-no prompt")
			}
		})
	}

	if ok, err := readYesNo(strings.NewReader("y\n"), brokenConfirmationWriter{}, "prompt"); ok || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("accepted despite failed prompt: %v %v", ok, err)
	}
}

type brokenConfirmationWriter struct{}

func (brokenConfirmationWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestShortPasswordPolicy(t *testing.T) {
	original := readConfirmation
	defer func() { readConfirmation = original }()

	for _, tc := range []struct {
		name, password      string
		accept              bool
		confirmErr          error
		wantPrompt, wantErr bool
	}{
		{name: "strong", password: "a longer random passphrase"},
		{name: "sixteen-unicode", password: strings.Repeat("猫", 16)},
		{name: "short-yes", password: "pw", accept: true, wantPrompt: true},
		{name: "short-no", password: "pw", wantPrompt: true, wantErr: true},
		{name: "short-unicode", password: strings.Repeat("猫", 8), accept: true, wantPrompt: true},
		{name: "confirmation-error", password: "pw", confirmErr: io.EOF, wantPrompt: true, wantErr: true},
		{name: "empty", accept: true, wantErr: true},
		{name: "whitespace", password: " \t ", accept: true, wantErr: true},
		{name: "oversize", password: strings.Repeat("x", limits.PasswordBytes+1), accept: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			readConfirmation = func(prompt string) (bool, error) {
				calls++

				if !strings.Contains(prompt, "easier to guess offline") {
					t.Fatal("missing risk warning")
				}

				return tc.accept, tc.confirmErr
			}
			err := validateNewPassword(tc.password)

			if (err != nil) != tc.wantErr || (calls == 1) != tc.wantPrompt || calls > 1 {
				t.Fatalf("err=%v confirmations=%d", err, calls)
			}
		})
	}
}
