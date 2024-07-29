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
	"crypto/sha256"
	"hash"
)

// HashFunc is a function that returns a hash.Hash.
type HashFunc = func() hash.Hash

// Credential represents a credential.
type Credential struct {
	username string
	password string
	hashFunc HashFunc
}

// CredentialOption represents an option for a credential.
type CredentialOption func(*Credential)

// NewCredential returns a new credential with options.
func NewCredential(opts ...CredentialOption) *Credential {
	cred := &Credential{
		username: "",
		password: "",
		hashFunc: sha256.New,
	}
	cred.SetOption(opts...)
	return cred
}

// WithUsername returns an option to set the username.
func WithUsername(username string) CredentialOption {
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

// WithHashFunc returns an option to set the hash function.
func WithHashFunc(hashFunc HashFunc) CredentialOption {
	return func(cred *Credential) {
		cred.hashFunc = hashFunc
	}
}

// SetOption sets the options.
func (cred *Credential) SetOption(opts ...CredentialOption) {
	for _, opt := range opts {
		opt(cred)
	}
}

// HashFunc returns the hash function.
func (cred *Credential) HashFunc() HashFunc {
	return cred.hashFunc
}

// Username returns the username.
func (cred *Credential) Username() string {
	return cred.username
}

// Password returns the password.
func (cred *Credential) Password() string {
	return cred.password
}

// HashPassword returns the hashed password.
func (cred *Credential) HashPassword() []byte {
	hash := cred.hashFunc()
	hash.Write([]byte(cred.password))
	return hash.Sum(nil)
}
