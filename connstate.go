// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

import (
	"crypto/tls"
	"strings"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// ConnState is a snapshot of the negotiated connection parameters, valid once
// the handshake has completed. Protocol classifies the handshake as "tlcp"
// (GB/T 38636), "tls12", or "tls13"; Profile reports whether the negotiated
// suite family is "gm" (SM2/SM3/SM4) or "standard". VersionID and
// CipherSuiteID are the crypto/tls constants matching the negotiated
// parameters; TLCP has no crypto/tls equivalent, so VersionID reports TLS 1.3
// because Go integrators (notably HTTP/2) reject lower versions.
type ConnState struct {
	NTLS          bool
	Protocol      string
	Profile       string
	Version       string
	Cipher        string
	ALPN          string
	ServerName    string
	SessionReused bool
	VersionID     uint16
	CipherSuiteID uint16
}

// State captures the connection state. Call it after a successful handshake;
// on a connection that has not completed the handshake the zero fields are
// returned alongside any accessor error.
func (c *Conn) State() ConnState {
	var state ConnState
	state.NTLS = c.IsNTLS()
	state.Version, _ = c.GetVersion()
	state.Cipher, _ = c.CurrentCipher()
	state.ALPN, _ = c.GetALPNNegotiated()
	state.SessionReused = c.SessionReused()
	state.ServerName = normalizeSNI(c.GetServername())
	if state.NTLS {
		state.Protocol = "tlcp"
		state.Profile = "gm"
	} else {
		switch state.Version {
		case "TLSv1.2":
			state.Protocol = "tls12"
		default:
			state.Protocol = "tls13"
		}
		if isGMCipher(state.Cipher) {
			state.Profile = "gm"
		} else {
			state.Profile = "standard"
		}
	}
	state.VersionID = tlsVersionID(state)
	state.CipherSuiteID = CipherSuiteID(state.Cipher)
	return state
}

// PeerIdentity is the verified client identity of the connection's peer
// certificate. crypto/x509 cannot faithfully parse SM2 certificates, so the
// identity is exposed as names and raw PEM instead of parsed certificates.
type PeerIdentity struct {
	Presented bool
	Verified  bool
	Subject   string
	Issuer    string
	Serial    string
	PEM       string
}

// PeerIdentity returns the peer certificate identity, or the zero value when
// the peer presented no certificate or it cannot be read.
func (c *Conn) PeerIdentity() PeerIdentity {
	cert, err := c.PeerCertificate()
	if err != nil {
		return PeerIdentity{}
	}
	identity := PeerIdentity{Presented: true, Verified: c.VerifyResult() == Ok}
	identity.Serial = cert.GetSerialNumberHex()
	identity.Subject = CertificateName(cert, true)
	identity.Issuer = CertificateName(cert, false)
	if pem, err := cert.MarshalPEM(); err == nil {
		identity.PEM = string(pem)
	}
	return identity
}

// CertificateName returns the subject (or issuer) name of cert formatted as
// "CN=<common name>", or "" when the name cannot be read. SM2 certificates
// cannot be parsed by crypto/x509, so this string form is the portable
// representation.
func CertificateName(cert *crypto.Certificate, subject bool) string {
	var (
		name *crypto.Name
		err  error
	)
	if subject {
		name, err = cert.GetSubjectName()
	} else {
		name, err = cert.GetIssuerName()
	}
	if err != nil {
		return ""
	}
	commonName, _ := name.GetEntry(crypto.NidCommonName)
	if commonName == "" {
		return ""
	}
	return "CN=" + commonName
}

// normalizeSNI lowercases the SNI value and strips one trailing dot, matching
// the server_name normalization used by crypto/tls.
func normalizeSNI(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func isGMCipher(name string) bool {
	return strings.Contains(name, "SM2") ||
		strings.Contains(name, "SM3") ||
		strings.Contains(name, "SM4")
}

func tlsVersionID(state ConnState) uint16 {
	if state.Protocol == "tls12" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

// CipherSuiteID maps a Tongsuo cipher name to its IANA cipher suite ID, or 0
// when the name is unknown.
func CipherSuiteID(name string) uint16 {
	switch name {
	case "TLS_SM4_GCM_SM3", "ECC-SM2-SM4-GCM-SM3", "ECDHE-SM2-SM4-GCM-SM3":
		return 0x00C6
	case "TLS_SM4_CCM_SM3":
		return 0x00C7
	case "TLS_AES_128_GCM_SHA256":
		return tls.TLS_AES_128_GCM_SHA256
	case "TLS_AES_256_GCM_SHA384":
		return tls.TLS_AES_256_GCM_SHA384
	case "TLS_CHACHA20_POLY1305_SHA256":
		return tls.TLS_CHACHA20_POLY1305_SHA256
	case "ECDHE-RSA-AES128-GCM-SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	case "ECDHE-RSA-AES256-GCM-SHA384":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	case "ECDHE-ECDSA-AES128-GCM-SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	case "ECDHE-ECDSA-AES256-GCM-SHA384":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	default:
		return 0
	}
}
