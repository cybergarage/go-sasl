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

package scram

// PropertyMap represents a SCRAM property map.
type PropertyMap map[string]Property

// NewPropertyMap returns a new SCRAM property map.
func NewPropertyMap() PropertyMap {
	return PropertyMap{}
}

// Property returns a property from the map.
func (m PropertyMap) Property(name string) (string, bool) {
	prop := m[name]
	if prop == nil {
		return "", false
	}
	return prop.Value(), true
}

// UserName returns the user name property from the map.
func (m PropertyMap) UserName() (string, bool) {
	return m.Property(UserName)
}

// FutureExtensions returns the future extensibility property from the map.
func (m PropertyMap) FutureFutureExtensibility() (string, bool) {
	return m.Property(FutureExtensibility)
}

// RandomSequence returns the random sequence property from the map.
func (m PropertyMap) RandomSequence() (string, bool) {
	return m.Property(RandomSequence)
}

// Salt returns the salt property from the map.
func (m PropertyMap) Salt() (string, bool) {
	return m.Property(Salt)
}

// IterationCount returns the iteration count property from the map.
func (m PropertyMap) IterationCount() (string, bool) {
	return m.Property(IterationCount)
}

// ClientProof returns the client proof property from the map.
func (m PropertyMap) ClientProof() (string, bool) {
	return m.Property(ClientProof)
}

// ServerSignature returns the server signature property from the map.
func (m PropertyMap) ServerSignature() (string, bool) {
	return m.Property(ServerSignature)
}

// Error returns the error property from the map.
func (m PropertyMap) Error() (string, bool) {
	return m.Property(Error)
}
