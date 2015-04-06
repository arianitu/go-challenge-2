package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// LengthPrefixer implements length-prefixing framing.
// TCP and other streaming communication channels do not work on frames, but work on a stream of data.
// A common technique to read in frames is to add a length before each message on a write, and then
// consume the length on a read. LengthPrefier does that for you on an underlying ReadWriteCloser
type LengthPrefixer struct {
	rw io.ReadWriteCloser
	maxLength uint32
}

// Init initializes the prefixer
// maxLength is the maximum message size that LengthPrefier will try to read (not including the uint32 header)
// rw is the underlying stream, such as tcp.Conn
func (l *LengthPrefixer) Init(rw io.ReadWriteCloser, maxLength uint32) {
	l.rw = rw
	l.maxLength = maxLength
}

// NewLengthPrefixer is a helper method that allocates a LengthPrefixer and initializes it for you
// maxLength is the maximum message size that LengthPrefier will try to read (not including the uin32 header)
// rw is the underlying stream, such as tcp.Conn
func NewLengthPrefixer(rw io.ReadWriteCloser, maxLength uint32) *LengthPrefixer {
	l := &LengthPrefixer{}
	l.Init(rw, maxLength)
	return l
}

// Write data to the underlying stream. The data is prefixed with a length. 
func (l *LengthPrefixer) Write(p []byte) (n int, err error) {
	length := uint32(len(p))
	err = binary.Write(l.rw, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	return l.rw.Write(p)
}

// Read data from the underlying stream. p is expected to be at least the size
// of the length prefix. If p is not at least the length of the prefix, Read will
// write as much as it can and then discard the rest of the message
func (l *LengthPrefixer) Read(p []byte) (n int, err error) {
	var length uint32
	err = binary.Read(l.rw, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	if length > l.maxLength {
		return 0, fmt.Errorf("Length prefix is too big!")
	}

	buf := make([]byte, length)
	n, err = io.ReadFull(l.rw, buf)
	if err != nil {
		return n, err
	}
	copy(p, buf)

	return n, nil
}

// Close closes the underlying stream
func (l *LengthPrefixer) Close() error {
	return l.rw.Close()
}
