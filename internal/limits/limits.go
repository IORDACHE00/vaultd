// Package limits centralizes supported input sizes. Limits reject oversized
// input rather than silently truncating secrets.
package limits

const (
	PasswordBytes       = 4096
	VaultBytes    int64 = 8 << 20
	SecretBytes   int64 = 64 << 10
	ProfileBytes  int64 = 64 << 10
	MarkerBytes   int64 = 1024
	ResponseBytes int64 = 16 << 20
)
