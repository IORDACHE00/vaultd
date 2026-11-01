package main

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/cmd"
	"github.com/IORDACHE00/vaultd/internal/hardening"
	"os"
)

func main() {
	if err := hardening.Process(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cmd.Execute()
}
