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
	authenticators []Authenticator
	credStore      cred.Store
}

// NewManager returns a new auth manager instance.
func NewManager() Manager {
	mgr := &manager{
		authenticators: make([]Authenticator, 0),
		credStore:      nil,
	}
	return mgr
}

// AddAuthenticators adds the specified authenticators.
func (mgr *manager) AddAuthenticators(authenticators ...Authenticator) {
	mgr.authenticators = append(mgr.authenticators, authenticators...)
}

// SetAuthenticators sets the specified authenticators.
func (mgr *manager) SetAuthenticators(authenticators ...Authenticator) {
	mgr.authenticators = make([]Authenticator, len(authenticators))
	copy(mgr.authenticators, authenticators)
}

// ClearAuthenticators clears all authenticators.
func (mgr *manager) ClearAuthenticators() {
	mgr.authenticators = make([]Authenticator, 0)
}

// Authenticators returns the registered authenticators.
func (mgr *manager) Authenticators() []Authenticator {
	return mgr.authenticators
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
	var errs error
	for _, authenticator := range mgr.authenticators {
		if v, ok := authenticator.(TLSAuthenticator); ok {
			ok, err := v.VerifyCertificate(conn, certs)
			if ok {
				return true, nil
			}
			errs = errors.Join(errs, err)
		}
	}
	return false, errs
}

// VerifyCredential verifies the client credential.
func (mgr *manager) VerifyCredential(conn net.Conn, q cred.Query) (bool, error) {
	if mgr.credStore == nil {
		return false, cred.ErrNoCredential
	}
	cred, err := mgr.credStore.LookupCredential(q)
	if err != nil {
		return false, err
	}
	var errs error
	for _, authenticator := range mgr.authenticators {
		if v, ok := authenticator.(CredentialAuthenticator); ok {
			ok, err := v.VerifyCredential(conn, q, cred)
			if ok {
				return true, nil
			}
			errs = errors.Join(errs, err)
		}
	}
	return false, errs
}
