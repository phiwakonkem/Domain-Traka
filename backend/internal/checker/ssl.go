package checker

import (
	"crypto/tls"
	"time"
)

type SSLResult struct {
	IsSuccess    bool
	ExpiresAt    time.Time
	ErrorMessage string
}

func CheckSSL(hostname string) SSLResult {
	dialer := &tls.Dialer{
		Config: &tls.Config{
		},
	}

	conn, err := dialer.Dial("tcp", hostname+":443")
	if err != nil {
		return SSLResult{
			IsSuccess:    false,
			ErrorMessage: err.Error(),
		}
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return SSLResult{
			IsSuccess:    false,
			ErrorMessage: "connection is not a TLS connection",
		}
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return SSLResult{
			IsSuccess:    false,
			ErrorMessage: "no certificates found",
		}
	}

	leafCert := certs[0]

	return SSLResult{
		IsSuccess: true,
		ExpiresAt: leafCert.NotAfter,
	}
}