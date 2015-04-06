package nacl

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
)

var (
	// MaxBoxLength is the maximum size we'll try to decrypt (excluding nonce header)
	MaxBoxLength = 31999
	// NonceHeaderLength is a fixed 24 bytes
	NonceHeaderLength = 24
)

// Reader wraps an underlying reader with a secure
//
type Reader struct {
	sharedKey [32]byte
	r         io.Reader
}

func NewReader(r io.Reader, priv, pub *[32]byte) *Reader {
	sr := &Reader{}
	sr.Init(r, priv, pub)
	return sr
}

func (sr *Reader) Init(r io.Reader, priv, pub *[32]byte) {
	box.Precompute(&sr.sharedKey, pub, priv)
	sr.r = r
}

func (sr *Reader) Read(p []byte) (n int, err error) {
	var nonce [24]byte

	encryptedData := make([]byte, NonceHeaderLength+MaxBoxLength+box.Overhead)
	n, err = sr.r.Read(encryptedData)
	if err != nil {
		return 0, err
	}

	copy(nonce[:], encryptedData[0:24])
	var decryptedData = make([]byte, 0)
	decryptedData, ok := box.OpenAfterPrecomputation(decryptedData, encryptedData[24:], &nonce, &sr.sharedKey)
	if !ok {
		return 0, fmt.Errorf("Failed to decrypt box! Message length must be smaller than 32KB!")
	}

	copy(p, decryptedData)
	return len(decryptedData), nil
}

type Writer struct {
	sharedKey [32]byte
	w         io.Writer
}

func NewWriter(w io.Writer, priv, pub *[32]byte) *Writer {
	sw := &Writer{}
	sw.Init(w, priv, pub)
	return sw
}

func (sw *Writer) Init(w io.Writer, priv, pub *[32]byte) {
	box.Precompute(&sw.sharedKey, pub, priv)
	sw.w = w
}

func (sw *Writer) Write(p []byte) (n int, err error) {
	var nonce [24]byte

	randomBytes := make([]byte, 24)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}
	copy(nonce[:], randomBytes[:])
	encryptedData := box.SealAfterPrecomputation(randomBytes, p, &nonce, &sw.sharedKey)

	written := 0
	n, err = sw.w.Write(encryptedData)
	if err != nil {
		return written + n, err
	}
	written += n
	return written, nil
}
