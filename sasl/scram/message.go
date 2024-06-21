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
	"strings"

	"github.com/cybergarage/go-sasl/sasl/gss"
)

// Message represents a SCRAM message.
type Message struct {
	*gss.Header
	AttributeMap
}

// NewMessage returns a new Message.
func NewMessage() *Message {
	msg := &Message{
		Header:       nil,
		AttributeMap: NewAttributeMap(),
	}
	return msg
}

// HasHeader returns true if the message has a GS2 header.
func (msg *Message) HasHeader() bool {
	return msg.Header != nil
}

// ParseStringWithHeader parses the specified string　with the GS2 header.
func (msg *Message) ParseStringWithHeader(str string) error {
	return msg.ParseStringsWithHeader(strings.Split(str, ","))
}

// ParseStringsWithHeader parses the specified property strings with the GS2 header.
func (msg *Message) ParseStringsWithHeader(props []string) error {
	var err error
	msg.Header, err = gss.NewHeaderFromStrings(props)
	if err != nil {
		return err
	}
	scramProps := props[gss.GS2PropertyMaxCount:]
	if !msg.Header.HasStdFlag() {
		scramProps = props[(gss.GS2PropertyMaxCount - 1):]
	}
	return msg.ParseStrings(scramProps)
}

// ParseStringWithHeader parses the specified string.
func (msg *Message) ParseString(str string) error {
	return msg.ParseStrings(strings.Split(str, ","))
}

// ParseStringsWithHeader parses the specified property strings.
func (msg *Message) ParseStrings(props []string) error {
	for _, scramProp := range props {
		if len(scramProp) < 2 || scramProp[1] != '=' {
			return newErrInvalidAttribute(scramProp)
		}
		attrName := scramProp[:1]
		attrValue := scramProp[2:]
		switch attrName {
		case UserName,
			FutureExtensibility,
			RandomSequence,
			ChannelBindingData,
			Salt,
			IterationCount,
			ClientProof,
			ServerSignature,
			Error:
			prop := NewAttribute(attrName, attrValue)
			msg.AttributeMap[attrName] = prop
		default:
			return newErrInvalidAttribute(scramProp)
		}
	}
	return nil
}

// Equals returns true if the message equals the specified message.
func (msg *Message) Equals(other *Message) bool {
	if msg.HasHeader() != other.HasHeader() {
		return false
	}
	if msg.HasHeader() && !msg.Header.Equals(other.Header) {
		return false
	}
	return msg.AttributeMap.Equals(other.AttributeMap)
}

// String returns the string representation of the message.
func (msg *Message) String() string {
	if !msg.HasHeader() {
		return msg.AttributeMap.String()
	}
	return msg.Header.String() + "," + msg.AttributeMap.String()
}
