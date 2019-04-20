package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"

	quic "github.com/lucas-clemente/quic-go"
)

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	if len(os.Args) > 2 {
		log.Fatal(echoServer(os.Args[1], os.Args[2]))
	} else {
		err := clientMain(os.Args[1])
		if err != nil {
			panic(err)
		}
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(port, address string) error {
	listener, err := quic.ListenAddr(port, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			stream, err := sess.AcceptStream()
			if err != nil {
				panic(err)
			}
			defer stream.Close()
			// Echo through the loggingWriter
			stream.Read(make([]byte, 1))
			upstream, err := net.Dial("tcp", address)
			if err != nil {
				panic(err)
			}
			defer upstream.Close()
			go io.Copy(upstream, stream)
			_, err = io.Copy(stream, upstream)
		}()
	}
}

func clientMain(addr string) error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}
	stream.Write([]byte{1})

	go io.Copy(stream, os.Stdin)
	io.Copy(os.Stdout, stream)

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
