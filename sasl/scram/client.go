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

// NewClientFirstMessage returns a new client first message.
func NewClientFirstMessage() *Message {
	msg := NewMessage()
	return msg
}

// NewClientFirstMessageFrom returns a new client first message from the specified string.
func NewClientFirstMessageFrom(msg string) (*Message, error) {
	if len(msg) == 0 {
		return NewClientFirstMessage(), nil
	}
	scramMsg := NewClientFirstMessage()
	err := scramMsg.ParseStringWithHeader(msg)
	if err != nil {
		return nil, err
	}

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5. SCRAM Authentication Exchange
	// Note that the client's first message will always start with "n", "y", or "p";
	// otherwise, the message is invalid and authentication MUST fail.
	cbFlag := scramMsg.CBFlag()
	if !cbFlag.IsValid() {
		return nil, newErrInvalidMessage(cbFlag.String())
	}

	return scramMsg, err
}

// NewClientFinalMessage returns a new client final message from the specified server message.
func NewClientFinalMessageFrom(serverMsg *Message) (*Message, error) {
	msg := NewMessage()
	return msg, nil
}
