package nacl

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"encoding/binary"
)

// This file implements a streaming version of nacl.box. 

var (
	// NonceHeaderLength is a fixed 24 bytes
	NonceHeaderLength = 24
)

// Reader wraps an underlying reader 
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

// Decrypts data
func (sr *Reader) Read(p []byte) (n int, err error) {

	var length uint32
	err = binary.Read(sr.r, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}

	encryptedData := make([]byte, length)
	n, err = io.ReadFull(sr.r, encryptedData)
	if err != nil {
		return 0, err
	}
	
	var nonce [24]byte
	copy(nonce[:], encryptedData[0:24])
	
	var decryptedData = make([]byte, 0)
	decryptedData, ok := box.OpenAfterPrecomputation(decryptedData, encryptedData[24:n], &nonce, &sr.sharedKey)
	if !ok {
		return 0, fmt.Errorf("Failed to decrypt box!")
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
	
	// rand.Read is guaranteed to read 24 bytes because it calls ReadFull under the covers
	nonceBytes := make([]byte, 24)
	_, err = rand.Read(nonceBytes)
	if err != nil {
		return 0, err
	}
	
	// We create a fixed array to copy the nonceBytes (there is no way to convert from slice to fixed array without copying)
	var nonce [24]byte
	copy(nonce[:], nonceBytes[:])
	
	// box.Seal takes `out` and appends the encrypted data to it and returns it (it does _not_ change `out`)
	// We pass nonceBytes to Seal so we get returned data in the form [nonce][encryptedData] 
	encryptedData := box.SealAfterPrecomputation(nonceBytes, p, &nonce, &sw.sharedKey)

	// Prepend the length to our data so the reader knows how much room to make when reading
	var length = uint32(len(encryptedData))
	err = binary.Write(sw.w, binary.LittleEndian, length)
	if err != nil {
		return 0, nil
	}

	written := 0
	n, err = sw.w.Write(encryptedData)
	if err != nil {
		return written + n, err
	}
	written += n
	return written, nil
}
