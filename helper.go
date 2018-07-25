package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/ocsp"
)

//Helper comment
type Helper struct {
	name string
}

//LoadCert comment
func LoadCert(certFile string, certKey string, chain []byte) (tls.Certificate, error) {
	if len(chain) == 0 {
		return tls.LoadX509KeyPair(certFile, certKey)
	}

	certData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	err = ioutil.WriteFile("tmpCertChain", append(certData, chain...), os.ModeAppend)

	cert, err := tls.LoadX509KeyPair("tmpCertChain", certKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	err = os.Remove("tmpCertChain")
	if err != nil {
		log.Printf("Could not delete temp file: %s", err)
	}

	return cert, nil
}

//VerifyPeerCertificate comment
func (h Helper) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for i := 0; i < len(verifiedChains); i++ {
		for j := 0; j < len(verifiedChains[i]); j++ {
			cCert := verifiedChains[i][j]
			isRoot := cCert.Subject.CommonName == cCert.Issuer.CommonName

			ocspInfo := ""
			if !isRoot {
				if err := CheckOCSP(cCert, verifiedChains[i][j+1]); err != nil {
					return err
				}
				ocspInfo = " including OCSP"
			}

			log.Printf("%s successfully validated certificate%s %s\n", h.name, ocspInfo, cCert.Subject)
		}
	}

	return nil
}

//CheckOCSP comment
func CheckOCSP(cert *x509.Certificate, issuerCert *x509.Certificate) error {
	if len(cert.OCSPServer) < 1 {
		return fmt.Errorf("certificate %s did not provide OCSP url", cert.Subject)
	}

	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}

	buffer, err := ocsp.CreateRequest(cert, issuerCert, opts)
	if err != nil {
		return fmt.Errorf("Could not create OCSP request for certificate %s: %s", cert.Subject, err)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		return fmt.Errorf("Could not create webrequest for OCSP-check for certificate %s: %s", cert.Subject, err)
	}
	ocspURL, err := url.Parse(cert.OCSPServer[0])
	if err != nil {
		return fmt.Errorf("Could not get url from OCSP field for certificate %s: %s", cert.Subject, err)
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("could not execute ocsp-web-check for certificate %s: %s", cert.Subject, err)
	}
	defer httpResponse.Body.Close()

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("Could not read OCSP-response for certificate %s: %s", cert.Subject, err)
	}
	ocspResponse, err := ocsp.ParseResponse(output, issuerCert)
	if err != nil {
		return fmt.Errorf("Could not parse OCSP-response for certificate %s: %s", cert.Subject, err)
	}
	if ocspResponse.Status != ocsp.Good {
		return fmt.Errorf("Certificate %s did not pass OCSP: %v", cert.Subject, OcspStatusText(ocspResponse))
	}

	return nil
}

//OcspStatusText comment
func OcspStatusText(resp *ocsp.Response) string {
	switch resp.Status {
	case ocsp.Good:
		return "Good"
	case ocsp.Revoked:
		reason := "Unknown"
		switch resp.RevocationReason {
		case ocsp.Unspecified:
			reason = "Unspecified"
		case ocsp.KeyCompromise:
			reason = "KeyCompromise"
		case ocsp.CACompromise:
			reason = "CACompromise"
		case ocsp.AffiliationChanged:
			reason = "AffiliationChanged"
		case ocsp.Superseded:
			reason = "Superseeded"
		case ocsp.CessationOfOperation:
			reason = "CessationOfOperation"
		case ocsp.CertificateHold:
			reason = "CertificateHold"
		case ocsp.RemoveFromCRL:
			reason = "RemoveFromCRL"
		case ocsp.PrivilegeWithdrawn:
			reason = "PriviledgeWithdrawn"
		case ocsp.AACompromise:
			reason = "AACompromise"
		}
		return fmt.Sprintf("Revoked at %v. Reason: %s", resp.RevokedAt, reason)
	case ocsp.Unknown:
		return "Unknown -> Not Good!"
	}
	return "This should no one ever see..."
}
