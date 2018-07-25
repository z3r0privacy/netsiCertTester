package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"log"
)

//StartServer comment
func StartServer(certFile string, keyFile string, rootCA *x509.CertPool, certChain []byte, c chan bool) {
	h := Helper{name: "Server"}

	cert, err := LoadCert(certFile, keyFile, certChain)
	if err != nil {
		c <- false
		log.Fatal(err)
	}

	config := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             rootCA,
		VerifyPeerCertificate: h.VerifyPeerCertificate,
	}

	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		c <- false
		log.Fatal(err)
	}

	defer ln.Close()

	log.Println("Server is listening")
	c <- true

	conn, err := ln.Accept()
	if err != nil {
		log.Printf("Server could not accept client: %s\n", err)
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	data, err := r.ReadString('\n')
	if err != nil {
		log.Printf("Server could not read from client: %s\n", err)
		return
	}

	_, err = conn.Write([]byte(data + "\n"))
	if err != nil {
		log.Printf("Server could not write to client: %s\n", err)
		return
	}

	log.Println("From server-side, everything looks good")
}
