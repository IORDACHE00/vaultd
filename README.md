# vaultd

**Encrypted, local secrets for your development workflows.** Store credentials in a password-protected vault and expose them only to the processes you launch—without putting secret values in shell history or command-line arguments.

## Get started

Requires Go 1.27.3 or later and Linux. Clone the repository, then build and run locally:

```sh
git clone https://github.com/IORDACHE00/vaultd.git
cd vaultd
go build -o vaultd .

./vaultd init                   # Create your encrypted vault
./vaultd profile use my-service # Choose this project's default profile
./vaultd set API_TOKEN          # Enter the value privately
./vaultd daemon -d              # Unlock the vault
./vaultd run -- npm run dev     # Start your app with its secrets
./vaultd daemon stop            # Stop the daemon
```

To install the binary into Go's bin directory instead, run `go install .` from the repository root. Ensure `$(go env GOPATH)/bin` is on your `PATH`, then use `vaultd` without the `./` prefix. Re-run `go install .` after pulling updates.

Use a strong, unique vault password. The vault is stored under `~/.vaultd`; project profile selection is saved in `.vaultd.json` and contains no secret values. Add the local config to your project’s `.gitignore` if you don't want to share it.

## How it works

- Secrets are encrypted at rest and organized by profile.
- `vaultd run -- <command>` fetches the selected profile and sets secrets in the launched process's environment. Your shell environment is unchanged.
- Secret entry is hidden; automation can use `vaultd set --stdin KEY < file`.
- An unlocked daemon serves requests over a private local Unix socket. It expires after 15 minutes by default.
- Optional Linux Secret Service integration can store the vault password in your OS keyring.

```sh
vaultd set DATABASE_URL
vaultd get DATABASE_URL              # Prints plaintext; handle output carefully
vaultd --profile staging set API_TOKEN
vaultd run --profile staging -- ./server
vaultd daemon --help
```

Profiles are organizational labels, not security boundaries between processes running as the same user. Any application receiving a secret can retain or disclose it.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

## License

MIT. See [LICENSE](LICENSE).
