package main

import (
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
)

func main() {
	rootCACertFile := flag.String("rootCA", "", "path to the certificate of the root ca")
	serverCertFile := flag.String("serverCert", "", "path to the certificate of the server")
	serverKeyFile := flag.String("serverKey", "", "path to the keyfile of the server certificate")
	clientCertFile := flag.String("clientCert", "", "path to the certificate of the client")
	clientKeyFile := flag.String("clientKey", "", "path to the keyfile of the client certificate")
	certChainFile := flag.String("certChain", "", "optional: if the server and client certificates do not include the whole certificate chain, specify the chain here")

	flag.Parse()
	if *rootCACertFile == "" {
		log.Fatal("rootCA was not specified")
	}
	if *serverCertFile == "" {
		log.Fatal("serverCert was not specified")
	}
	if *serverKeyFile == "" {
		log.Fatal("serverKey was not specified")
	}
	if *clientCertFile == "" {
		log.Fatal("clientCert was not specified")
	}
	if *clientKeyFile == "" {
		log.Fatal("clientKey was not specified")
	}

	rootCAData, err := ioutil.ReadFile(*rootCACertFile)
	if err != nil {
		log.Fatal(err)
	}
	rootCA := x509.NewCertPool()
	ok := rootCA.AppendCertsFromPEM(rootCAData)
	if !ok {
		log.Fatal("Could not load root CA")
	}

	var certChain []byte

	if *certChainFile != "" {
		certChain, err = ioutil.ReadFile(*certChainFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	c := make(chan bool)
	go StartServer(*serverCertFile, *serverKeyFile, rootCA, certChain, c)

	if <-c {
		StartClient(*clientCertFile, *clientKeyFile, rootCA, certChain)
	}
}
