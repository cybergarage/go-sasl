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

// EncryptFunc represents an encrypt function.
type EncryptFunc func(passwd any, args ...any) (any, error)

// Query represents a query interface.
type Query interface {
	// SetGroup sets the group.
	SetGroup(group string)
	// SetUsername sets the username.
	SetUsername(username string)
	// SetPassword sets the password.
	SetPassword(password any)
	// SetMechanism sets the mechanism.
	SetMechanism(mech string)
	// SetOptions sets the options.
	SetOptions(opts ...any)
	// SetArguments sets the arguments.
	SetArguments(args ...any)
	// SetEncryptFunc sets the encrypt function.
	SetEncryptFunc(encryptFunc EncryptFunc)
	// Group returns the group.
	Group() string
	// Username returns the username.
	Username() string
	// Password returns the password.
	Password() any
	// Mechanism returns the mechanism.
	Mechanism() string
	// Options returns the options.
	Options() []any
	// EncryptFunc returns the encrypt function.
	EncryptFunc() EncryptFunc
	// Arguments returns the arguments for the encrypt function.
	Arguments() []any
}
