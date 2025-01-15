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

// cred represents a credential.
type cred struct {
	group    string
	username string
	password any
}

// CredentialOptionFn represents an option for a credential.
type CredentialOptionFn func(*cred)

// NewCredential returns a new credential with options.
func NewCredential(opts ...CredentialOptionFn) Credential {
	cred := &cred{
		group:    "",
		username: "",
		password: "",
	}
	cred.SetOption(opts...)
	return cred
}

// WithCredentialGroup returns an option to set the group.
func WithCredentialGroup(group string) CredentialOptionFn {
	return func(cred *cred) {
		cred.group = group
	}
}

// WithCredentialUsername returns an option to set the username.
func WithCredentialUsername(username string) CredentialOptionFn {
	return func(cred *cred) {
		cred.username = username
	}
}

// WithCredentialPassword returns an option to set the password.
func WithCredentialPassword(password any) CredentialOptionFn {
	return func(cred *cred) {
		cred.password = password
	}
}

// SetOption sets the options.
func (cred *cred) SetOption(opts ...CredentialOptionFn) {
	for _, opt := range opts {
		opt(cred)
	}
}

// Group returns the group.
func (cred *cred) Group() string {
	return cred.group
}

// Username returns the username.
func (cred *cred) Username() string {
	return cred.username
}

// Password returns the password.
func (cred *cred) Password() any {
	return cred.password
}
