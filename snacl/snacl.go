/*

Package snacl wraps nacl around a Reader/Writer so it's easy to compose with other Reader/Writers (such as a TCP connection.) It
also handles nonces for you.

*/
package snacl

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
)

// Reader decrypts from a stream securely using nacl
type Reader struct {
	sharedKey [32]byte
	r         io.Reader
}

// NewReader is a convenient helper method that allocates and initializes a secure reader for you
// r is the underlying stream to read securely from
// priv is your private key
// pub is the public key of who you're communicating with
func NewReader(r io.Reader, priv, pub *[32]byte) *Reader {
	sr := &Reader{}
	sr.Init(r, priv, pub)
	return sr
}

// Init initializes our Reader
// r is the underlying stream to read securely from
// priv is your private key
// pub is the public key of who you're communicating with
func (sr *Reader) Init(r io.Reader, priv, pub *[32]byte) {
	box.Precompute(&sr.sharedKey, pub, priv)
	sr.r = r
}

// Read decrypts a box in the underlying stream and writes it to p []byte
func (sr *Reader) Read(p []byte) (n int, err error) {

	// Length is the length of the encrypted data (including box.Overhead)
	var length uint32
	err = binary.Read(sr.r, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}

	// To be able to decrypt properly, we must receive all the data that we encrypted with
	encryptedData := make([]byte, length)
	n, err = io.ReadFull(sr.r, encryptedData)
	if err != nil {
		return 0, err
	}

	var nonce [24]byte
	copy(nonce[:], encryptedData[0:24])

	// OpenAfterPrecomputation appends to out and returns the appended data
	var decryptedData = make([]byte, 0)
	decryptedData, ok := box.OpenAfterPrecomputation(decryptedData, encryptedData[24:], &nonce, &sr.sharedKey)

	// If ok is false, we have failed to decrypt properly
	// Usually this is because the encrypted data is malformed
	if !ok {
		return 0, fmt.Errorf("Failed to decrypt box! Encrypted data is likely malformed.")
	}

	n = copy(p, decryptedData)
	return n, nil
}

// Writer encrypts data securely to a stream using nacl
type Writer struct {
	sharedKey [32]byte
	w         io.Writer
}

// NewWriter is a convenient helper method that allocates and initializes a secure writer for you
// W is the underlying stream to write securely to
// priv is your private key
// pub is the public key of who you're communicating with
func NewWriter(w io.Writer, priv, pub *[32]byte) *Writer {
	sw := &Writer{}
	sw.Init(w, priv, pub)
	return sw
}

// Init initializes our Writer.
// w is the underlying stream to write securely to
// priv is your private key
// pub is the public key of who you're communicating with
func (sw *Writer) Init(w io.Writer, priv, pub *[32]byte) {
	box.Precompute(&sw.sharedKey, pub, priv)
	sw.w = w
}

// Write encrypts p []byte to the underlying stream.
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

	// box.SealAfterPrecomputation appends the encrypted data to it out and returns it
	// We pass nonceBytes to the out parameter so we get returned data in the form [nonce][encryptedData]
	encryptedData := box.SealAfterPrecomputation(nonceBytes, p, &nonce, &sw.sharedKey)

	// Prepend the length to our data so the reader knows how much room to make when reading
	var length = uint32(len(encryptedData))
	err = binary.Write(sw.w, binary.LittleEndian, length)
	if err != nil {
		return 0, nil
	}

	n, err = sw.w.Write(encryptedData)
	if err != nil {
		return n, err
	}
	return n, nil
}
