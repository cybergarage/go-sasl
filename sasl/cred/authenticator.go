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

package cred

// Authenticator represents an authenticator interface.
type Authenticator interface {
	// HasCredential returns true if the authenticator has the specified username.
	HasCredential(q *Query) (*Credential, bool)
}

// Authenticators represents a list of authenticators.
type Authenticators []Authenticator

// NewAuthenticators returns a new Authenticators.
func NewAuthenticators(auths ...Authenticator) Authenticators {
	return Authenticators(auths)
}
