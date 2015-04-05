package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/arianitu/go-challenge-2/nacl"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
)

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return nacl.NewReader(r, priv, pub)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return nacl.NewWriter(w, priv, pub)
}

type SecureConnection struct {
	sr   *nacl.Reader
	sw   *nacl.Writer
	conn net.Conn
}

func (sconn *SecureConnection) Init(conn net.Conn, priv, pub *[32]byte) {
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

type KeyRandomizer struct{}

func (r *KeyRandomizer) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// Client: generate private/public key for self
// Server: generate private/public key for self
//
// swap public keys..

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	clientPublicKey, clientPrivateKey, err := box.GenerateKey(&KeyRandomizer{})

	var serverPublicKey [32]byte
	_, err = conn.Read(serverPublicKey[:])
	if err != nil {
		return nil, err
	}

	conn.Write(clientPublicKey[:])
	secureConnection := &SecureConnection{}
	secureConnection.Init(conn, clientPrivateKey, &serverPublicKey)

	return secureConnection, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			serverPublicKey, serverPrivateKey, err := box.GenerateKey(&KeyRandomizer{})
			c.Write(serverPublicKey[:])

			var clientPublicKey [32]byte
			_, err = c.Read(clientPublicKey[:])
			if err != nil {
				fmt.Println(err)
			}
			secureConnection := &SecureConnection{}
			secureConnection.Init(c, serverPrivateKey, &clientPublicKey)

			buf := make([]byte, 31999)
			read, err := secureConnection.Read(buf)
			if err != nil {
				fmt.Println(err)
			}

			_, err = secureConnection.Write(buf[:read])
			if err != nil {
				fmt.Println(err)
			}
		}(conn)
	}
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
			return
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
