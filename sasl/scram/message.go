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

// ParseString parses the specified string.
func (msg *Message) ParseString(str string) error {
	return msg.ParseStrings(strings.Split(str, ","))
}

// ParseStrings parses the specified property strings.
func (msg *Message) ParseStrings(props []string) error {
	var err error
	msg.Header, err = gss.NewHeaderFromStrings(props)
	if err != nil {
		return err
	}
	scramProps := props[gss.GS2PropertyMaxCount:]
	if !msg.Header.HasStdFlag() {
		scramProps = props[(gss.GS2PropertyMaxCount - 1):]
	}
	for _, scramProp := range scramProps {
		scramProps := strings.Split(scramProp, "=")
		if len(scramProps) < 2 {
			return newErrInvalidAttribute(scramProp)
		}
		attrName := scramProps[0]
		switch scramProps[0] {
		case UserName,
			FutureExtensibility,
			RandomSequence,
			ChannelBindingData,
			Salt,
			IterationCount,
			ClientProof,
			ServerSignature,
			Error:
			prop := NewAttribute(attrName, scramProps[1])
			msg.AttributeMap[attrName] = prop
		default:
			return newErrInvalidAttribute(scramProp)
		}
	}
	return nil
}
