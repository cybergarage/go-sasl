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

// Provider represents a SASL mechanism provider.
type Provider interface {
	// AddMechanism adds a mechanism to the server.
	AddMechanism(mech Mechanism)
	// AddMechanisms adds mechanisms to the server.
	AddMechanisms(mech ...Mechanism)
	// Mechanisms returns all mechanisms.
	Mechanisms() []Mechanism
	// Mechanism returns a mechanism by name.
	Mechanism(name string) (Mechanism, error)
}
