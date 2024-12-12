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

// CredentialStore represent an credential store.
type CredentialStore struct {
	authenticators []Authenticator
}

// NewCredentialStore returns a new credential store.
func NewCredentialStore() *CredentialStore {
	manager := &CredentialStore{
		authenticators: make([]Authenticator, 0),
	}
	return manager
}

// AddAuthenticator adds a new authenticator.
func (mgr *CredentialStore) AddAuthenticator(authenticator Authenticator) {
	mgr.authenticators = append(mgr.authenticators, authenticator)
}

// AddAuthenticators adds the specified authenticators.
func (mgr *CredentialStore) AddAuthenticators(authenticators Authenticators) {
	mgr.authenticators = append(mgr.authenticators, authenticators...)
}

// SetAuthenticators sets the specified authenticators.
func (mgr *CredentialStore) SetAuthenticators(authenticators Authenticators) {
	mgr.authenticators = make([]Authenticator, len(authenticators))
	copy(mgr.authenticators, authenticators)
}

// ClearAuthenticators clears all authenticators.
func (mgr *CredentialStore) ClearAuthenticators() {
	mgr.authenticators = make([]Authenticator, 0)
}

// Authenticators returns the authenticators.
func (mgr *CredentialStore) Authenticators() Authenticators {
	return mgr.authenticators
}

// HasCredential returns true if the username has a credential.
func (mgr *CredentialStore) HasCredential(q Query) (Credential, error) {
	for _, authenticator := range mgr.authenticators {
		if cred, ok := authenticator.HasCredential(q); ok {
			return cred, nil
		}
	}
	return nil, ErrNoCredential
}
