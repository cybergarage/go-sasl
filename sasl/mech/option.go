// Copyright (C) 2024 The go-sasl Authors. All rights reserved.
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

package mech

import (
	"hash"

	"github.com/cybergarage/go-sasl/sasl/cred"
)

// Option represents a SASL mechanism option.
type Option = any

// Group represents a group option.
type Group string

// Username represents a username option.
type Username string

// Password represents a password option.
type Password string

// Token represents a token.
type Token string

// Email represents an email.
type Email string

// Payload represents a payload.
type Payload []byte

// Authenticators represents a list of credential authenticators.
type Authenticators = cred.Authenticators

// HashFunc represents a hash function.
type RandomSequence string

// IterationCount represents an iteration count.
type IterationCount int

// HashFunc represents a hash function.
type HashFunc func() hash.Hash

// Salt represents a salt.
type Salt []byte
