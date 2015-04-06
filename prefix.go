package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

type LengthPrefixer struct {
	rw io.ReadWriteCloser
}

func (l *LengthPrefixer) Init(rw io.ReadWriteCloser) {
	l.rw = rw
}

func NewLengthPrefixer(rw io.ReadWriteCloser) *LengthPrefixer {
	l := &LengthPrefixer{}
	l.Init(rw)
	return l
}

func (l *LengthPrefixer) Write(p []byte) (n int, err error) {
	var length uint32 = uint32(len(p))
	err = binary.Write(l.rw, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	return l.rw.Write(p)
}

func (l *LengthPrefixer) Read(p []byte) (n int, err error) {
	var length uint32
	err = binary.Read(l.rw, binary.LittleEndian, &length)
	if err != nil {
		return 0, err
	}
	if length > 31999 {
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

func (l *LengthPrefixer) Close() error {
	return l.rw.Close()
}
