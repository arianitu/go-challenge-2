package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
	"crypto/rand"
	"github.com/arianitu/go-challenge-2/nacl"
)

var (
	maxMessageLength = uint32(31999 + nacl.NonceHeaderLength + box.Overhead)
)

// CryptoRandomReader generates cryptographically random data
type CryptoRandomReader struct{}

// Read will put random data into p, it will try to fill p entirely with random data
func (r *CryptoRandomReader) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return nacl.NewReader(r, priv, pub)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return nacl.NewWriter(w, priv, pub)
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// We don't use LengthPrefixer on the key to satisfy the way the tests communicate
	clientPublicKey, clientPrivateKey, err := box.GenerateKey(new(CryptoRandomReader))
	var serverPublicKey [32]byte
	_, err = io.ReadAtLeast(conn, serverPublicKey[:], 32)
	if err != nil {
		return nil, err
	}
	conn.Write(clientPublicKey[:])

	// Frame any messages from this point on
	framedConn := NewLengthPrefixer(conn, maxMessageLength)
	secureConnection := &SecureConnection{}
	secureConnection.Init(framedConn, clientPrivateKey, &serverPublicKey)

	return secureConnection, nil
}

// Serve starts a secure echo server on the given listener.
// Messages are run through a pipeline
// Sending:
// [data] -> nacl.Writer -> [nonce][encrypted_data] -> LengthPrefixer -> [length][nonce][encrypted_data] -> socket
// Receving:
// socket -> [length][nonce][encrypted_data] -> LengthPrefixer -> [length][nonce][encrypted_data] -> nacl.Reader -> [data]
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()

			// We don't use LengthPrefixer on the key to satisfy the way the tests communicate
			serverPublicKey, serverPrivateKey, err := box.GenerateKey(new(CryptoRandomReader))
			conn.Write(serverPublicKey[:])

			var clientPublicKey [32]byte
			_, err = io.ReadAtLeast(conn, clientPublicKey[:], 32)
			if err != nil {
				fmt.Println(err)
				return
			}

			// Frame any messages from this point on.
			framedConn := NewLengthPrefixer(conn, maxMessageLength)
			secureConnection := &SecureConnection{}
			secureConnection.Init(framedConn, serverPrivateKey, &clientPublicKey)

			// In a typical server, we'd re-use this buffer for each message
			// and the maximum would be a lot smaller than 32kb.
			buf := make([]byte, maxMessageLength)
			read, err := secureConnection.Read(buf)
			if err != nil {
				fmt.Println(err)
				return
			}

			_, err = secureConnection.Write(buf[:read])
			if err != nil {
				fmt.Println(err)
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
