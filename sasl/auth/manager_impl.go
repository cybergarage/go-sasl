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
	"crypto/x509"
	"errors"
	"net"

	"github.com/cybergarage/go-sasl/sasl/cred"
)

type manager struct {
	tlsAuthenticator  TLSAuthenticator
	credAuthenticator CredentialAuthenticator
	credStore         cred.Store
}

// NewManager returns a new auth manager instance.
func NewManager() Manager {
	mgr := &manager{
		credStore:         nil,
		tlsAuthenticator:  NewDefaultCertificateAuthenticator(),
		credAuthenticator: NewDefaultCredentialAuthenticator(),
	}
	return mgr
}

// SetCredentialAuthenticator sets the credential authenticator.
func (mgr *manager) SetCredentialAuthenticator(auth CredentialAuthenticator) {
	mgr.credAuthenticator = auth
}

// SetTLSAuthenticator sets the TLS authenticator.
func (mgr *manager) SetTLSAuthenticator(auth TLSAuthenticator) {
	mgr.tlsAuthenticator = auth
}

// SetCredentialStore sets the credential store.
func (mgr *manager) SetCredentialStore(credStore cred.Store) {
	mgr.credStore = credStore
}

// CredentialStore returns the credential store.
func (mgr *manager) CredentialStore() cred.Store {
	return mgr.credStore
}

// VerifyCertificate verifies the client certificate.
func (mgr *manager) VerifyCertificate(conn tls.Conn, certs []*x509.Certificate) (bool, error) {
	if mgr.tlsAuthenticator == nil {
		return false, errors.New("no TLS authenticator")
	}
	return mgr.tlsAuthenticator.VerifyCertificate(conn, certs)
}

// VerifyCredential verifies the client credential.
func (mgr *manager) VerifyCredential(conn net.Conn, q cred.Query) (bool, error) {
	if mgr.credStore == nil || mgr.credAuthenticator == nil {
		return false, cred.ErrNoCredential
	}
	cred, err := mgr.credStore.LookupCredential(q)
	if err != nil {
		return false, err
	}
	return mgr.credAuthenticator.VerifyCredential(conn, q, cred)
}
