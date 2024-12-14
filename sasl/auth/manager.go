// Copyright (C) 2019 The go-sasl Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"crypto/tls"

	"github.com/cybergarage/go-sasl/sasl/cred"
)

// Manager represents a  auth manager interface.
type Manager interface {
	// SetCredentialAuthenticator sets the credential authenticator.
	SetCredentialAuthenticator(auth CredentialAuthenticator)
	// SetCertificateAuthenticator sets the certificate authenticator.
	SetCertificateAuthenticator(auth CertificateAuthenticator)
	// SetCredentialStore sets the credential store.
	SetCredentialStore(credStore cred.Store)
	// CredentialStore returns the credential store.
	CredentialStore() cred.Store
	// VerifyCertificate verifies the client certificate.
	VerifyCertificate(conn Conn, state tls.ConnectionState) (bool, error)
	// VerifyCredential verifies the client credential.
	VerifyCredential(conn Conn, q cred.Query) (bool, error)
}
