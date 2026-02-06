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

type provider struct {
	mechanismMap map[string]Mechanism
}

// NewProvider creates a new provider.
func NewProvider() Provider {
	provider := &provider{
		mechanismMap: make(map[string]Mechanism),
	}
	return provider
}

// AddMechanism adds a mechanism to the server.
func (provider *provider) AddMechanism(mech Mechanism) {
	provider.mechanismMap[mech.Name()] = mech
}

// AddMechanisms adds mechanisms to the server.
func (provider *provider) AddMechanisms(mech ...Mechanism) {
	for _, m := range mech {
		provider.AddMechanism(m)
	}
}

// Mechanisms returns all mechanisms.
func (provider *provider) Mechanisms() []Mechanism {
	mechs := make([]Mechanism, 0, len(provider.mechanismMap))
	for _, mech := range provider.mechanismMap {
		mechs = append(mechs, mech)
	}
	return mechs
}

// Mechanism returns a mechanism by name.
func (provider *provider) Mechanism(name string) (Mechanism, error) {
	mech, ok := provider.mechanismMap[name]
	if !ok {
		return nil, newErrUnsupportedMechanism(name)
	}
	return mech, nil
}
