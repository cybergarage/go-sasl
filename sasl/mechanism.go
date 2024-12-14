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

package sasl

import "github.com/cybergarage/go-sasl/sasl/mech"

// Mechanism represents a SASL mechanism.
type Mechanism = mech.Mechanism

// Parameter represents a SASL mechanism parameter.
type Parameter = mech.Parameter

// Response represents a SASL mechanism response.
type Response = mech.Response

// Context represents a SASL mechanism context.
type Context = mech.Context

// Option represents a SASL mechanism option.
type Option = mech.Option

// Group represents a group option.
type Group = mech.Group

// AuthzID represents an authorization ID option.
type AuthzID = mech.AuthzID

// Username represents a username option.
type Username = mech.Username

// Password represents a password option.
type Password = mech.Password

// Token represents a token.
type Token = mech.Token

// Email represents an email.
type Email = mech.Email

// Payload represents a payload.
type Payload = mech.Payload

// RandomSequence represents a random sequence.
type RandomSequence = mech.RandomSequence

// IterationCount represents an iteration count.
type IterationCount = mech.IterationCount

// HashFunc represents a hash function.
type HashFunc = mech.HashFunc

// Challenge represents a challenge.
type Challenge = mech.Challenge

// Salt represents a salt.
type Salt = mech.Salt
