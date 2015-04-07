package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	
	"github.com/arianitu/go-challenge-2/snacl"
)

var (
	maxMessageLength = 31999
)

// CryptoRandomReader generates crypto random data
type CryptoRandomReader struct{}

// Read will put random data into p, it will try to fill p entirely with random data
func (r *CryptoRandomReader) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// SecureConnection implements a secure connection using public-key cryptography
type SecureConnection struct {
	sr   io.Reader
	sw   io.Writer
	conn io.ReadWriteCloser
}

// Init initializes the secure connection with a private and public key
// conn is an underlying connection
// priv is your private key
// pub is the public key of the party you're trying to communicate with
func (sconn *SecureConnection) Init(conn io.ReadWriteCloser, priv, pub *[32]byte) {
	sconn.sr = NewSecureReader(conn, priv, pub)
	sconn.sw = NewSecureWriter(conn, priv, pub)
	sconn.conn = conn
}

// Read decrypts from the underlying stream and writes it to p []byte
func (sconn *SecureConnection) Read(p []byte) (n int, err error) {
	return sconn.sr.Read(p)
}

// Write encrypts p []byte and sends it to the underlying stream
func (sconn *SecureConnection) Write(p []byte) (n int, err error) {
	return sconn.sw.Write(p)
}

// Close closes the underlying stream
func (sconn *SecureConnection) Close() error {
	return sconn.conn.Close()
}

// NewSecureConnection allocates a SecureConnection for you and initializes it
func NewSecureConnection(r io.ReadWriteCloser, priv, pub *[32]byte) *SecureConnection {
	secureConnection := &SecureConnection{}
	secureConnection.Init(r, priv, pub)
	return secureConnection
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return snacl.NewReader(r, priv, pub)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return snacl.NewWriter(w, priv, pub)
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	clientPublicKey, clientPrivateKey, err := box.GenerateKey(new(CryptoRandomReader))
	var serverPublicKey [32]byte
	_, err = io.ReadAtLeast(conn, serverPublicKey[:], 32)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(clientPublicKey[:])
	if err != nil {
		return nil, err
	}

	return NewSecureConnection(conn, clientPrivateKey, &serverPublicKey), nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()

			serverPublicKey, serverPrivateKey, err := box.GenerateKey(new(CryptoRandomReader))
			_, err = conn.Write(serverPublicKey[:])
			if (err != nil) {
				log.Println(err)
				return
			}

			var clientPublicKey [32]byte
			_, err = io.ReadFull(conn, clientPublicKey[:])
			if err != nil {
				log.Println(err)
				return
			}

			secureConnection := NewSecureConnection(conn, serverPrivateKey, &clientPublicKey)

			buf := make([]byte, maxMessageLength)
			read, err := secureConnection.Read(buf)
			if err != nil {
				log.Println(err)
				return
			}

			_, err = secureConnection.Write(buf[:read])
			if err != nil {
				log.Println(err)
				return
			}
		}(conn)
	}
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
