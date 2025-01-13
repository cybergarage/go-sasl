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
type EncryptFunc func(query Query) (string, error)

// Query represents a query interface.
type Query interface {
	// Group returns the group.
	Group() string
	// Username returns the username.
	Username() string
	// Password returns the password.
	Password() string
	// Mechanism returns the mechanism.
	Mechanism() string
	// Options returns the options.
	Options() []any
	// EncryptFunc returns the encrypt function.
	EncryptFunc() EncryptFunc
	// Arguments returns the arguments for the encrypt function.
	Arguments() []any
}
