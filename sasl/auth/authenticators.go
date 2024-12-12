// Copyright (C) 2024 The go-mysql Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/cybergarage/go-sasl/sasl/cred"
)

// Credential represents a credential interface.
type Credential = cred.Credential

// TLSAuthenticator is the interface for authenticating a client using TLS.
type TLSAuthenticator interface {
	// VerifyCertificate verifies the client certificate.
	VerifyCertificate(conn tls.Conn, certs []*x509.Certificate) error
}

// CredentialAuthenticator is the interface for authenticating a client using credential.
type CredentialAuthenticator interface {
	// VerifyCredential verifies the client credential.
	VerifyCredential(conn net.Conn, cred Credential) error
}
