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

// cred represents a credential.
type cred struct {
	group    string
	username string
	password string
}

// credOptionFn represents an option for a credential.
type credOptionFn func(*cred)

// NewCredential returns a new credential with options.
func NewCredential(opts ...credOptionFn) Credential {
	cred := &cred{
		group:    "",
		username: "",
		password: "",
	}
	cred.SetOption(opts...)
	return cred
}

// WithCredentialGroup returns an option to set the group.
func WithCredentialGroup(group string) credOptionFn {
	return func(cred *cred) {
		cred.group = group
	}
}

// WithCredentialUsername returns an option to set the username.
func WithCredentialUsername(username string) credOptionFn {
	return func(cred *cred) {
		cred.username = username
	}
}

// WithCredentialPassword returns an option to set the password.
func WithCredentialPassword(password string) credOptionFn {
	return func(cred *cred) {
		cred.password = password
	}
}

// SetOption sets the options.
func (cred *cred) SetOption(opts ...credOptionFn) {
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
func (cred *cred) Password() string {
	return cred.password
}

// Authorize returns true if the credential is authorized.
func (cred *cred) Authorize(q Query) bool {
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
