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

// Manager represent an credential store.
type Manager struct {
	authenticators []Authenticator
}

// NewManager returns a new Manager.
func NewManager() *Manager {
	mgr := &Manager{
		authenticators: make([]Authenticator, 0),
	}
	return mgr
}

// AddAuthenticator adds a new authenticator.
func (mgr *Manager) AddAuthenticator(authenticator Authenticator) {
	mgr.authenticators = append(mgr.authenticators, authenticator)
}

// AddAuthenticators adds the specified authenticators.
func (mgr *Manager) AddAuthenticators(authenticators Authenticators) {
	mgr.authenticators = append(mgr.authenticators, authenticators...)
}

// SetAuthenticators sets the specified authenticators.
func (mgr *Manager) SetAuthenticators(authenticators Authenticators) {
	mgr.authenticators = make([]Authenticator, len(authenticators))
	copy(mgr.authenticators, authenticators)
}

// ClearAuthenticators clears all authenticators.
func (mgr *Manager) ClearAuthenticators() {
	mgr.authenticators = make([]Authenticator, 0)
}

// Authenticators returns the authenticators.
func (mgr *Manager) Authenticators() Authenticators {
	return mgr.authenticators
}