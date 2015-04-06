package main

import (
	"crypto/rand"
)

// box.GenerateKey requires an io.Reader to generate keys. We wrap
// rand.Read() to satisfy it.
type CryptoRandomReader struct{}

func (r *CryptoRandomReader) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}
