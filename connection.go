package main

import (
	"github.com/arianitu/go-challenge-2/nacl"
	"io"
)

type SecureConnection struct {
	sr   *nacl.Reader
	sw   *nacl.Writer
	conn io.ReadWriteCloser
}

func (sconn *SecureConnection) Init(conn io.ReadWriteCloser, priv, pub *[32]byte) {
	sconn.sr = nacl.NewReader(conn, priv, pub)
	sconn.sw = nacl.NewWriter(conn, priv, pub)
	sconn.conn = conn
}

func (sconn *SecureConnection) Read(p []byte) (n int, err error) {
	return sconn.sr.Read(p)
}

func (sconn *SecureConnection) Write(p []byte) (n int, err error) {
	return sconn.sw.Write(p)
}

func (sconn *SecureConnection) Close() error {
	return sconn.conn.Close()
}
