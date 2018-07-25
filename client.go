package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"log"
	"math/rand"
	"strconv"
)

//StartClient comment
func StartClient(clientCertFile string, clientKeyFile string, rootCA *x509.CertPool, certChain []byte) {
	h := Helper{name: "Client"}

	cert, err := LoadCert(clientCertFile, clientKeyFile, certChain)
	if err != nil {
		log.Fatal(err)
	}

	conf := &tls.Config{
		RootCAs:               rootCA,
		Certificates:          []tls.Certificate{cert},
		ServerName:            "server.netsi.lab",
		VerifyPeerCertificate: h.VerifyPeerCertificate,
	}

	conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
	if err != nil {
		log.Fatalf("Client could not connect to server: %s", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)

	rng := rand.Intn(1000)
	_, err = conn.Write([]byte(strconv.Itoa(rng) + "\n"))
	if err != nil {
		log.Fatalf("Client could not send test data to server: %s", err)
	}

	data, err := r.ReadString('\n')
	if err != nil {
		log.Fatalf("Client could not read data from server: %s", err)
	}
	nr, err := strconv.Atoi(data[:len(data)-1])
	if err != nil {
		log.Fatalf("Server returned wrong data to client: %s", err)
	}

	if nr != rng {
		log.Fatalf("Server returned wrong data to client. Sent: %d, received: %d", rng, nr)
	}

	log.Println("From client-side, everything looks good")
}
