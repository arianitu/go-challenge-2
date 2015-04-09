package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

var (
	// MaxMessageLength is the maximum size a of a message. This is prevent memory allocation attacks.
	MaxMessageLength  = 31999
	nonceHeaderLength = 24
)

// CryptoRandomReader generates crypto random data
type CryptoRandomReader struct{}

// Read will put random data into p, it will try to fill p entirely with random data
func (r *CryptoRandomReader) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// SecureReadWriteCloser implements a secure ReadWriteCloser using public-key cryptography
type SecureReadWriteCloser struct {
	sr  *SecureReader
	sw  *SecureWriter
	rwc io.ReadWriteCloser
}

// Init initializes a SecureWriteCloser with a private and public key
// rwc is an underlying ReadWriteCloser we want to make secure
// priv is your private key
// pub is the public key of the party you're trying to communicate with
func (srwc *SecureReadWriteCloser) Init(rwc io.ReadWriteCloser, priv, pub *[32]byte) {
	srwc.sr = NewSecureReader(rwc, priv, pub)
	srwc.sw = NewSecureWriter(rwc, priv, pub)
	srwc.rwc = rwc
}

// Read decrypts from the underlying stream and writes it to p []byte
// p is expected to be big enough to hold the entire decrypted message, if it's not,
// Read writes as much as it can and discards the rest of the message.
func (srwc *SecureReadWriteCloser) Read(msg []byte) (n int, err error) {
	return srwc.sr.Read(msg)
}

// ReadMsg decrypts an entire box from the underlying stream and returns it
func (srwc *SecureReadWriteCloser) ReadMsg() (msg []byte, err error) {
	return srwc.sr.ReadMsg()
}

// Write encrypts p []byte and sends it to the underlying stream
func (srwc *SecureReadWriteCloser) Write(msg []byte) (n int, err error) {
	return srwc.sw.Write(msg)
}

// Close closes the underlying stream
func (srwc *SecureReadWriteCloser) Close() error {
	return srwc.rwc.Close()
}

// NewSecureReadWriteCloser allocates a SecureReadWriteCloser for you and initializes it
func NewSecureReadWriteCloser(r io.ReadWriteCloser, priv, pub *[32]byte) *SecureReadWriteCloser {
	srwc := &SecureReadWriteCloser{}
	srwc.Init(r, priv, pub)
	return srwc
}

// SecureReader decrypts from a stream securely using nacl
type SecureReader struct {
	sharedKey [32]byte
	r         io.Reader
}

// NewSecureReader is a convenient helper method that allocates and initializes a secure reader for you
// r is the underlying stream to read securely from
// priv is your private key
// pub is the public key of who you're communicating with
func NewSecureReader(r io.Reader, priv, pub *[32]byte) *SecureReader {
	sr := &SecureReader{}
	sr.Init(r, priv, pub)
	return sr
}

// Init initializes our Reader
// r is the underlying stream to read securely from
// priv is your private key
// pub is the public key of who you're communicating with
func (sr *SecureReader) Init(r io.Reader, priv, pub *[32]byte) {
	box.Precompute(&sr.sharedKey, pub, priv)
	sr.r = r
}

// ReadMsg decrypts an entire message from the underlying stream and returns it
func (sr *SecureReader) ReadMsg() (msg []byte, err error) {
	// Length is the length of the encrypted data (including box.Overhead)
	var length uint32
	err = binary.Read(sr.r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length <= 0 {
		return nil, fmt.Errorf("invalid length (len:%d) for encrypted data", length)
	}
	// restrict length to stop memory allocation attack
	maxLength := uint32(MaxMessageLength + nonceHeaderLength + box.Overhead)
	if length > maxLength {
		return nil, fmt.Errorf("length of encrypted data is too large (len:%d max: %d)", length, maxLength)
	}

	// To be able to decrypt properly, we must receive all the data that we encrypted with
	encryptedData := make([]byte, length)
	_, err = io.ReadFull(sr.r, encryptedData)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], encryptedData[0:24])

	// OpenAfterPrecomputation appends to out and returns the appended data
	msg, ok := box.OpenAfterPrecomputation(msg, encryptedData[24:], &nonce, &sr.sharedKey)

	// If ok is false, we have failed to decrypt properly
	// Usually this is because the encrypted data is malformed
	if !ok {
		return nil, fmt.Errorf("failed to decrypt box! Encrypted data is likely malformed")
	}

	return msg, nil
}

// Read decrypts a box from the underlying stream and writes it to p []byte
// p is expected to be big enough to hold the entire decrypted message, if it's not,
// Read writes as much as it can to p []byte and discards the rest of the message.
func (sr *SecureReader) Read(p []byte) (n int, err error) {
	msg, err := sr.ReadMsg()
	if err != nil {
		return 0, err
	}

	n = copy(p, msg)
	return n, nil
}

// SecureWriter encrypts data securely to a stream
type SecureWriter struct {
	sharedKey [32]byte
	w         io.Writer
}

// NewSecureWriter is a convenient helper method that allocates and initializes a secure writer for you
// w is the underlying stream to write securely to
// priv is your private key
// pub is the public key of who you're communicating with
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) *SecureWriter {
	sw := &SecureWriter{}
	sw.Init(w, priv, pub)
	return sw
}

// Init initializes our Writer.
// w is the underlying stream to write securely to
// priv is your private key
// pub is the public key of who you're communicating with
func (sw *SecureWriter) Init(w io.Writer, priv, pub *[32]byte) {
	box.Precompute(&sw.sharedKey, pub, priv)
	sw.w = w
}

// Write encrypts p []byte to the underlying stream.
// the length of p is restricted to MaxMessageLength
func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	if len(p) > MaxMessageLength {
		return 0, fmt.Errorf("length is too large (len:%d max: %d)", len(p), MaxMessageLength)
	}

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
	err = binary.Write(sw.w, binary.BigEndian, length)
	if err != nil {
		return 0, nil
	}

	n, err = sw.w.Write(encryptedData)
	if err != nil {
		return n, err
	}
	return n, nil

}
