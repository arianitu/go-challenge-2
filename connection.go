package main

import (
	"github.com/arianitu/go-challenge-2/nacl"
	"io"
)

// SecureConnection implements a secure connection using public-key cryptography
type SecureConnection struct {
	sr   *nacl.Reader
	sw   *nacl.Writer
	conn io.ReadWriteCloser
}

// Init initializes the secure connection with a private and public key
// Conn is an underlying connection
// priv is your private key
// pub is the public key of the person you're trying to communicate with
func (sconn *SecureConnection) Init(conn io.ReadWriteCloser, priv, pub *[32]byte) {
	sconn.sr = nacl.NewReader(conn, priv, pub)
	sconn.sw = nacl.NewWriter(conn, priv, pub)
	sconn.conn = conn
}

// Read reads 
func (sconn *SecureConnection) Read(p []byte) (n int, err error) {
	return sconn.sr.Read(p)
}

// Write writes
func (sconn *SecureConnection) Write(p []byte) (n int, err error) {
	return sconn.sw.Write(p)
}

// Close closes the underlying connection
func (sconn *SecureConnection) Close() error {
	return sconn.conn.Close()
}
