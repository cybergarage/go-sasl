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
	"fmt"
	"strings"

	"github.com/cybergarage/go-sasl/sasl/gss"
	"github.com/cybergarage/go-sasl/sasl/mech"
)

// Message represents a SCRAM message.
type Message struct {
	*gss.Header
	AttributeMap
}

// MessageOption represents a message option.
type MessageOption func(*Message)

// NewMessage returns a new Message.
func NewMessage(opts ...MessageOption) *Message {
	msg := &Message{
		Header:       nil,
		AttributeMap: NewAttributeMap(),
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// NewMessageFromError returns a new Message from the specified error.
func NewMessageFromError(err error) *Message {
	msg := NewMessage()
	msg.SetError(err.Error())
	return msg
}

// WithHeader returns an option to set the GS2 header.
func WithHeader(header *gss.Header) MessageOption {
	return func(msg *Message) {
		msg.Header = header
	}
}

func WithAttribute(name, value string) MessageOption {
	return func(msg *Message) {
		msg.AttributeMap.SetAttribute(name, value)
	}
}

// NewMessageFrom returns a new Message from the specified value.
func NewMessageFrom(v any) (*Message, error) {
	switch v := v.(type) {
	case *Message:
		return v, nil
	case string:
		return NewMessageFromString(v)
	case []byte:
		return NewMessageFromString(string(v))
	case mech.Payload:
		return NewMessageFromString(string(v))
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("invalid message type")
}

// NewMessageFromWithHeader returns a new Message from the specified value with the GS2 header.
func NewMessageFromWithHeader(v any) (*Message, error) {
	switch v := v.(type) {
	case *Message:
		return v, nil
	case string:
		return NewMessageFromStringWithHeader(v)
	case []byte:
		return NewMessageFromStringWithHeader(string(v))
	case mech.Payload:
		return NewMessageFromStringWithHeader(string(v))
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("invalid message type")
}

// NewMessageFromString returns a new Message from the specified string.
func NewMessageFromString(msg string) (*Message, error) {
	scramMsg := NewMessage()
	err := scramMsg.ParseString(msg)
	return scramMsg, err
}

// NewMessageFromStringWithHeader returns a new Message from the specified string with the GS2 header.
func NewMessageFromStringWithHeader(msg string) (*Message, error) {
	scramMsg := NewMessage()
	err := scramMsg.ParseStringWithHeader(msg)
	return scramMsg, err
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
		case UserNameAttr,
			FutureExtensibilityAttr,
			RandomSequenceAttr,
			ChannelBindingDataAttr,
			SaltAttr,
			IterationCountAttr,
			ClientProofAttr,
			ServerSignatureAttr,
			ErrorAttr:
			msg.SetAttribute(attrName, attrValue)
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
	return msg.Header.String() + msg.AttributeMap.String()
}

// StringWithoutProof returns the string representation of the message without the proof.
func (msg *Message) StringWithoutProof() string {
	if !msg.HasHeader() {
		return msg.AttributeMap.StringWithoutProof()
	}
	return msg.Header.String() + msg.AttributeMap.StringWithoutProof()
}

// Bytes returns the message bytes.
func (msg *Message) Bytes() []byte {
	return []byte(msg.String())
}
