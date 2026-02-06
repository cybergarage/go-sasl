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

import (
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	"github.com/cybergarage/go-sasl/sasl/util"
)

// AttributeMap represents a SCRAM attribute map.
type AttributeMap struct {
	keys  []string
	attrs map[string]Attribute
}

// NewAttributeMap returns a new SCRAM attribute map.
func NewAttributeMap() AttributeMap {
	return AttributeMap{
		keys:  make([]string, 0),
		attrs: make(map[string]Attribute),
	}
}

// Attribute returns an attribute from the map.
func (m *AttributeMap) Attribute(name string) (string, bool) {
	prop := m.attrs[name]
	if prop == nil {
		return "", false
	}
	return prop.Value(), true
}

// DecodeAttribute returns a base64 decoded attribute from the map.
func (m *AttributeMap) DecodeAttribute(name string) ([]byte, bool) {
	v, ok := m.Attribute(name)
	if !ok {
		return nil, false
	}
	dv, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, false
	}
	return dv, true
}

// AuthorizationID returns the authorization ID attribute from the map.
func (m *AttributeMap) AuthorizationID() (string, bool) {
	return m.Attribute(AuthorizationIDAttr)
}

// Username returns the user name attribute from the map.
func (m *AttributeMap) Username() (string, bool) {
	v, ok := m.Attribute(UserNameAttr)
	if ok {
		v = util.DecodeName(v)
	}
	return v, ok
}

// FutureFutureExtensibility returns the future extensibility attribute from the map.
func (m *AttributeMap) FutureFutureExtensibility() (string, bool) {
	return m.Attribute(FutureExtensibilityAttr)
}

// RandomSequence returns the random sequence attribute from the map.
func (m *AttributeMap) RandomSequence() (string, bool) {
	return m.Attribute(RandomSequenceAttr)
}

// Salt returns the salt attribute from the map.
func (m *AttributeMap) Salt() ([]byte, bool) {
	return m.DecodeAttribute(SaltAttr)
}

// IterationCount returns the iteration count attribute from the map.
func (m *AttributeMap) IterationCount() (int, bool) {
	v, ok := m.Attribute(IterationCountAttr)
	if !ok {
		return 0, false
	}
	cnt, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return cnt, true
}

// ClientProof returns the client proof attribute from the map.
func (m *AttributeMap) ClientProof() ([]byte, bool) {
	return m.DecodeAttribute(ClientProofAttr)
}

// ChannelBindingData returns the channel binding data attribute from the map.
func (m *AttributeMap) ChannelBindingData() (string, bool) {
	return m.Attribute(ChannelBindingDataAttr)
}

// ServerSignature returns the server signature attribute from the map.
func (m *AttributeMap) ServerSignature() ([]byte, bool) {
	return m.DecodeAttribute(ServerSignatureAttr)
}

// Error returns the error attribute from the map.
func (m *AttributeMap) Error() (string, bool) {
	return m.Attribute(ErrorAttr)
}

// SetAttribute sets an attribute to the map.
func (m *AttributeMap) SetAttribute(name, value string) {
	m.attrs[name] = NewAttribute(name, value)
	// add name if it is not already in the list
	if slices.Contains(m.keys, name) {
		return
	}
	m.keys = append(m.keys, name)
}

// EncodeAttribute sets a base64 encoded attribute to the map.
func (m *AttributeMap) EncodeAttribute(name string, value []byte) {
	m.SetAttribute(name, base64.StdEncoding.EncodeToString(value))
}

// SetUsername sets the user name attribute to the map.
func (m *AttributeMap) SetUsername(value string) {
	m.SetAttribute(UserNameAttr, util.EncodeName(value))
}

// SetFutureExtensibility sets the future extensibility attribute to the map.
func (m *AttributeMap) SetFutureExtensibility(value string) {
	m.SetAttribute(FutureExtensibilityAttr, value)
}

// SetRandomSequence sets the random sequence attribute to the map.
func (m *AttributeMap) SetRandomSequence(value string) {
	m.SetAttribute(RandomSequenceAttr, value)
}

// SetSalt sets the salt attribute to the map.
func (m *AttributeMap) SetSalt(value string) {
	m.SetAttribute(SaltAttr, value)
}

// SetSaltBytes sets the salt attribute to the map.
func (m *AttributeMap) SetSaltBytes(value []byte) {
	m.EncodeAttribute(SaltAttr, value)
}

// SetIterationCount sets the iteration count attribute to the map.
func (m *AttributeMap) SetIterationCount(value int) {
	m.SetAttribute(IterationCountAttr, strconv.Itoa(value))
}

// SetClientProof sets the client proof attribute to the map.
func (m *AttributeMap) SetClientProof(value []byte) {
	m.EncodeAttribute(ClientProofAttr, value)
}

// SetChannelBindingData sets the channel binding data attribute to the map.
func (m *AttributeMap) SetChannelBindingData(value string) {
	m.SetAttribute(ChannelBindingDataAttr, value)
}

// SetServerSignature sets the server signature attribute to the map.
func (m *AttributeMap) SetServerSignature(value []byte) {
	m.EncodeAttribute(ServerSignatureAttr, value)
}

// SetError sets the error attribute to the map.
func (m *AttributeMap) SetError(value string) {
	m.SetAttribute(ErrorAttr, value)
}

// Equals returns true if the map is equal to the other map.
func (m *AttributeMap) Equals(other AttributeMap) bool {
	if len(m.attrs) != len(other.attrs) {
		return false
	}
	for name, prop := range m.attrs {
		otherProp, ok := other.attrs[name]
		if !ok {
			return false
		}
		if prop.Value() != otherProp.Value() {
			return false
		}
	}
	return true
}

// String returns the string representation of the map.
func (m *AttributeMap) String() string {
	attrs := []string{}
	for _, key := range m.keys {
		attr := m.attrs[key]
		attrs = append(attrs, key+"="+attr.Value())
	}
	return strings.Join(attrs, ",")
}

// StringWithoutProof returns the string representation of the map without the proof.
func (m *AttributeMap) StringWithoutProof() string {
	attrs := []string{}
	for _, key := range m.keys {
		if key == ClientProofAttr {
			continue
		}
		attr := m.attrs[key]
		attrs = append(attrs, key+"="+attr.Value())
	}
	return strings.Join(attrs, ",")
}
