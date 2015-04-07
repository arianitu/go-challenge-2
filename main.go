package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

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

	return NewSecureReadWriteCloser(conn, clientPrivateKey, &serverPublicKey), nil
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
			if err != nil {
				log.Println(err)
				return
			}

			var clientPublicKey [32]byte
			_, err = io.ReadFull(conn, clientPublicKey[:])
			if err != nil {
				log.Println(err)
				return
			}

			secureConnection := NewSecureReadWriteCloser(conn, serverPrivateKey, &clientPublicKey)

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
