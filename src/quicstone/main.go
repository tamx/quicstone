package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"

	quic "github.com/lucas-clemente/quic-go"
)

func help() {
	usage := "\n" +
		"client y.cane.jp:443 :10022:ssh :13389:rdp\n" +
		"server -l 0.0.0.0:443 ssh:localhost:22 rdp:Windows10:3389\n"
	log.Println(usage)
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	if len(os.Args) < 3 {
		help()
	} else if os.Args[1] == "-l" {
		log.Fatal(echoServer(os.Args[2],
			parseALPNforServer(os.Args[3:])))
	} else {
		err := clientMain(os.Args[1],
			parseALPNforClient(os.Args[2:]))
		if err != nil {
			log.Println(err)
		}
	}
}

type ALPNMap struct {
	Proto   string
	TCPPort string
}

func parseALPNforServer(params []string) []*ALPNMap {
	result := []*ALPNMap{}
	for _, param := range params {
		index := strings.Index(param, ":")
		if index <= 0 {
			help()
			os.Exit(0)
		}
		alpn := &ALPNMap{
			TCPPort: param[(index + 1):],
			Proto:   param[:(index)],
		}
		result = append(result, alpn)
	}
	return result
}

func parseALPNforClient(params []string) []*ALPNMap {
	result := []*ALPNMap{}
	for _, param := range params {
		index := strings.LastIndex(param, ":")
		if index <= 0 {
			help()
			os.Exit(0)
		}
		alpn := &ALPNMap{
			TCPPort: param[:(index)],
			Proto:   param[(index + 1):],
		}
		result = append(result, alpn)
	}
	return result
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(listenPort string, addrs []*ALPNMap) error {
	protos := []string{
		"echo",
	}
	for _, alpn := range addrs {
		protos = append(protos, alpn.Proto)
	}

	listener, err := quic.ListenAddr(listenPort,
		generateTLSConfig(protos), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		proto := sess.ConnectionState().NegotiatedProtocol
		log.Println("Proto: " + proto)
		if proto == "echo" {
			go func() {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					log.Println(err)
					return
				}
				defer stream.Close()
				stream.Write([]byte("全集中 水の呼吸 八の型！\n"))
			}()
			continue
		}
		for _, alpn := range addrs {
			if alpn.Proto == proto {
				address := alpn.TCPPort
				go func() {
					stream, err := sess.AcceptStream(context.Background())
					if err != nil {
						log.Println(err)
						return
					}
					defer stream.Close()
					upstream, err := net.Dial("tcp", address)
					if err != nil {
						log.Println(err)
						return
					}
					defer upstream.Close()
					go io.Copy(upstream, stream)
					_, err = io.Copy(stream, upstream)
				}()
			}
		}
	}
}

func clientMain(dAddr string, addrs []*ALPNMap) error {
	errCh := make(chan error, 1)
	for _, alpn := range addrs {
		addr := alpn.TCPPort
		proto := alpn.Proto
		go func() {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Println(err)
				errCh <- err
				return
			}
			for {
				connection, err := listener.Accept()
				if err != nil {
					log.Println(err)
					errCh <- err
					return
				}
				log.Println(proto)
				go func() {
					session, err := quic.DialAddr(dAddr,
						&tls.Config{InsecureSkipVerify: true,
							NextProtos: []string{proto},
						}, nil)
					if err != nil {
						log.Println(err)
						return
					}

					defer connection.Close()
					stream, err := session.
						OpenStreamSync(context.Background())
					if err != nil {
						log.Println(err)
						return
					}
					// stream.Write([]byte{0})
					go io.Copy(stream, connection)
					io.Copy(connection, stream)
				}()
			}
		}()
	}
	err := <-errCh
	return err
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig(protos []string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader,
		&template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   protos,
	}
}
