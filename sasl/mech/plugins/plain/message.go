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

package plain

import (
	"fmt"
	"strings"
)

// The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
// https://datatracker.ietf.org/doc/html/rfc4616

// Message represents a SASL PLAIN message.
type Message struct {
	authzid string
	authcid string
	passwd  string
}

// NewMessage returns a new message.
func NewMessage() *Message {
	return &Message{
		authzid: "",
		authcid: "",
		passwd:  "",
	}
}

// NewMessageWith returns a new message with the given authzid, authcid, and passwd.
func NewMessageWith(authzid, authcid, passwd string) *Message {
	return &Message{
		authzid: authzid,
		authcid: authcid,
		passwd:  passwd,
	}
}

// NewMessageFrom returns a new message from the given value.
func NewMessageFrom(v any) (*Message, error) {
	switch v := v.(type) {
	case *Message:
		return v, nil
	case []byte:
		msg := NewMessage()
		if err := msg.ParseBytes(v); err != nil {
			return nil, err
		}
		return msg, nil
	}
	return nil, fmt.Errorf("invalid type %T for PLAIN message", v)
}

// Authzid returns the authorization identity.
func (msg *Message) Authzid() string {
	return msg.authzid
}

// Authcid returns the authentication identity.
func (msg *Message) Authcid() string {
	return msg.authcid
}

// Passwd returns the password.
func (msg *Message) Passwd() string {
	return msg.passwd
}

// ParseBytes parses the message bytes.
func (msg *Message) ParseBytes(b []byte) error {
	strs := strings.Split(string(b), "\x00")
	if len(strs) < 3 {
		return fmt.Errorf("invalid PLAIN message")
	}
	msg.authzid = strs[0]
	msg.authcid = strs[1]
	msg.passwd = strs[2]
	return nil
}

// Bytes returns the message bytes.
func (msg *Message) Bytes() []byte {
	return []byte(msg.authzid + "\x00" + msg.authcid + "\x00" + msg.passwd)
}

// String returns the message string.
func (msg *Message) String() string {
	return fmt.Sprintf("%s,%s,%s", msg.authzid, msg.authcid, msg.passwd)
}
