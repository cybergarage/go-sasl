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

// AttributeMap represents a SCRAM attribute map.
type AttributeMap map[string]Attribute

// NewAttributeMap returns a new SCRAM attribute map.
func NewAttributeMap() AttributeMap {
	return AttributeMap{}
}

// Attribute returns an attribute from the map.
func (m AttributeMap) Attribute(name string) (string, bool) {
	prop := m[name]
	if prop == nil {
		return "", false
	}
	return prop.Value(), true
}

// UserName returns the user name attribute from the map.
func (m AttributeMap) UserName() (string, bool) {
	return m.Attribute(UserName)
}

// FutureExtensions returns the future extensibility attribute from the map.
func (m AttributeMap) FutureFutureExtensibility() (string, bool) {
	return m.Attribute(FutureExtensibility)
}

// RandomSequence returns the random sequence attribute from the map.
func (m AttributeMap) RandomSequence() (string, bool) {
	return m.Attribute(RandomSequence)
}

// Salt returns the salt attribute from the map.
func (m AttributeMap) Salt() (string, bool) {
	return m.Attribute(Salt)
}

// IterationCount returns the iteration count attribute from the map.
func (m AttributeMap) IterationCount() (string, bool) {
	return m.Attribute(IterationCount)
}

// ClientProof returns the client proof attribute from the map.
func (m AttributeMap) ClientProof() (string, bool) {
	return m.Attribute(ClientProof)
}

// ChannelBindingData returns the channel binding data attribute from the map.
func (m AttributeMap) ChannelBindingData() (string, bool) {
	return m.Attribute(ChannelBindingData)
}

// ServerSignature returns the server signature attribute from the map.
func (m AttributeMap) ServerSignature() (string, bool) {
	return m.Attribute(ServerSignature)
}

// Error returns the error attribute from the map.
func (m AttributeMap) Error() (string, bool) {
	return m.Attribute(Error)
}
