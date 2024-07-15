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

// AuthManager represent an authenticator manager.
type AuthManager struct {
	authenticators []Authenticator
}

// NewAuthManager returns a new authenticator manager.
func NewAuthManager() *AuthManager {
	manager := &AuthManager{
		authenticators: make([]Authenticator, 0),
	}
	return manager
}

// AddAuthenticator adds a new authenticator.
func (mgr *AuthManager) AddAuthenticator(authenticator Authenticator) {
	mgr.authenticators = append(mgr.authenticators, authenticator)
}

// ClearAuthenticators clears all authenticators.
func (mgr *AuthManager) ClearAuthenticators() {
	mgr.authenticators = make([]Authenticator, 0)
}

// HasCredential returns true if the username has a credential.
func (mgr *AuthManager) HasCredential(username string) bool {
	for _, authenticator := range mgr.authenticators {
		if authenticator.HasCredential(username) {
			return true
		}
	}
	return false
}
