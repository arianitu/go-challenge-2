package nacl

import (
	"golang.org/x/crypto/nacl/box"
	"io"
	"crypto/rand"
	"io/ioutil"
)

type Reader struct {
	sharedKey [32]byte
	r io.Reader
}

func NewReader(r io.Reader, priv, pub *[32]byte) *Reader {
	sr := &Reader{}
	sr.Init(r, priv, pub)
	return sr
}

func (sr *Reader) Init(r io.Reader, priv, pub *[32]byte) {
	box.Precompute(&sr.sharedKey, pub, priv)
	sr.r = r
}

func (sr *Reader) Read(p []byte) (n int, err error) {
	var nonce[24]byte
	encryptedData, err := ioutil.ReadAll(sr.r)
	
	if err != nil {
		return 0, nil;
	}
	
	copy(nonce[:], encryptedData[0:24])
	decryptedData := make([]byte, 0)
	decryptedData, ok := box.OpenAfterPrecomputation(decryptedData, encryptedData[24:], &nonce, &sr.sharedKey)
	if ! ok {
		panic("WTF is this bool")
	}
	
	copy(p, decryptedData)
	return len(decryptedData), nil
}

type Writer struct {
	sharedKey [32]byte
	w io.Writer
}

func NewWriter(w io.Writer, priv, pub *[32]byte) *Writer {
	sw := &Writer{}
	sw.Init(w, priv, pub)
	return sw
}

func (sw *Writer) Init(w io.Writer, priv, pub *[32]byte) {
	box.Precompute(&sw.sharedKey, pub, priv)
	sw.w = w
}

func (sw *Writer) Write(p []byte) (n int, err error) {	
	var nonce [24]byte
	randomBytes := make([]byte, 24)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}	
	copy(nonce[:], randomBytes[:])
	
	encryptedData := make([]byte, 0)
	encryptedData = box.SealAfterPrecomputation(encryptedData, p, &nonce, &sw.sharedKey)
	
	written := 0
	n, err = sw.w.Write(nonce[:])
	if err != nil {
		return written + n, err
	}
	written += n
	
	n, err = sw.w.Write(encryptedData)
	if err != nil {
		return written + n, err
	}
	written += n
	return written, nil
}

