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
	"github.com/cybergarage/go-sasl/sasl/cred"
)

type manager struct {
	credAuthenticator CredentialAuthenticator
	credStore         cred.Store
}

// NewManager returns a new auth manager instance.
func NewManager() Manager {
	mgr := &manager{
		credStore:         nil,
		credAuthenticator: NewDefaultCredentialAuthenticator(),
	}
	return mgr
}

// SetCredentialAuthenticator sets the credential authenticator.
func (mgr *manager) SetCredentialAuthenticator(auth CredentialAuthenticator) {
	mgr.credAuthenticator = auth
}

// SetCredentialStore sets the credential store.
func (mgr *manager) SetCredentialStore(credStore cred.Store) {
	mgr.credStore = credStore
}

// CredentialStore returns the credential store.
func (mgr *manager) CredentialStore() cred.Store {
	return mgr.credStore
}

// VerifyCredential verifies the client credential query.
// If the query is valid, the function returns true and no error.
// Otherwise, it returns false and an error if an error occurs during the verification process.
func (mgr *manager) VerifyCredential(conn Conn, q cred.Query) (bool, error) {
	if mgr.credStore == nil || mgr.credAuthenticator == nil {
		return false, cred.ErrNoCredential
	}
	cred, ok, err := mgr.credStore.LookupCredential(q)
	if !ok {
		return false, err
	}
	return mgr.credAuthenticator.VerifyCredential(conn, q, cred)
}
