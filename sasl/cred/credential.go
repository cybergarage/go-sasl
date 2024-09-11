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

// Credential represents a credential.
type Credential struct {
	group    string
	username string
	password string
}

// CredentialOption represents an option for a credential.
type CredentialOption func(*Credential)

// NewCredential returns a new credential with options.
func NewCredential(opts ...CredentialOption) *Credential {
	cred := &Credential{
		group:    "",
		username: "",
		password: "",
	}
	cred.SetOption(opts...)
	return cred
}

// WithCredentialGroup returns an option to set the group.
func WithCredentialGroup(group string) CredentialOption {
	return func(cred *Credential) {
		cred.group = group
	}
}

// WithCredentialUsername returns an option to set the username.
func WithCredentialUsername(username string) CredentialOption {
	return func(cred *Credential) {
		cred.username = username
	}
}

// WithPassword returns an option to set the password.
func WithPassword(password string) CredentialOption {
	return func(cred *Credential) {
		cred.password = password
	}
}

// SetOption sets the options.
func (cred *Credential) SetOption(opts ...CredentialOption) {
	for _, opt := range opts {
		opt(cred)
	}
}

// Group returns the group.
func (cred *Credential) Group() string {
	return cred.group
}

// Username returns the username.
func (cred *Credential) Username() string {
	return cred.username
}

// Password returns the password.
func (cred *Credential) Password() string {
	return cred.password
}

// Authorize returns true if the credential is authorized.
func (cred *Credential) Authorize(q *Query) bool {
	if 0 < len(cred.group) {
		if cred.group != q.Group() {
			return false
		}
	}
	if cred.username != q.Username() {
		return false
	}
	if cred.password != q.Password() {
		return false
	}
	return true
}
