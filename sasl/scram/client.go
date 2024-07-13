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

	"github.com/cybergarage/go-sasl/sasl/util"
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Client is a SCRAM client.
type Client struct {
	authzID  string
	username string
	password string
	hashFunc HashFunc
}

// NewClient returns a new SCRAM client with options.
func NewClient(opts ...(func(*Client) error)) (*Client, error) {
	client := &Client{
		authzID:  "",
		username: "",
		password: "",
		hashFunc: HashSHA256(),
	}
	for _, opt := range opts {
		err := opt(client)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// WithAuthzID returns an option to set the authorization ID.
func WithAuthzID(authzID string) func(*Client) error {
	return func(client *Client) error {
		client.authzID = authzID
		return nil
	}
}

// WithUsername returns an option to set the username.
func WithUsername(username string) func(*Client) error {
	return func(client *Client) error {
		client.username = username
		return nil
	}
}

// WithPassword returns an option to set the password.
func WithPassword(password string) func(*Client) error {
	return func(client *Client) error {
		client.password = password
		return nil
	}
}

// WithHashFunc returns an option to set the hash function.
func WithHashFunc(hashFunc HashFunc) func(*Client) error {
	return func(client *Client) error {
		client.hashFunc = hashFunc
		return nil
	}
}

// FirstMessage returns the first message.
func (client *Client) FirstMessage() (*Message, error) {
	msg := NewMessage()

	seq, err := rand.NewRandomSequence(initialRandomSequenceLength)
	if err != nil {
		return nil, err
	}
	msg.SetRandomSequence(string(seq))

	return msg, nil
}

// NewClientFirstMessageFrom returns a new client first message from the specified string.
func NewClientFirstMessageFrom(msg string) (*Message, error) {
	if len(msg) == 0 {
		return NewClientFirstMessage()
	}

	scramMsg, err := NewClientFirstMessage()
	if err != nil {
		return nil, err
	}
	err = scramMsg.ParseStringWithHeader(msg)
	if err != nil {
		return nil, err
	}

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5. SCRAM Authentication Exchange
	cbFlag := scramMsg.CBFlag()
	if !cbFlag.IsValid() {
		return nil, newErrInvalidMessage(msg)
	}
	// 5.1. SCRAM Attributes
	user, ok := scramMsg.AuthorizationID()
	if !ok {
		user, ok = scramMsg.UserName()
		if !ok {
			return nil, newErrInvalidMessage(msg)
		}
	}
	user = util.DecodeName(user)
	if len(user) == 0 {
		return nil, newErrInvalidMessage(msg)
	}
	return scramMsg, err
}

// NewClientFinalMessage returns a new client final message from the specified server message.
func NewClientFinalMessageFrom(hashFunc HashFunc, password string, clientFirsttMsg *Message, serverFirsttMsg *Message) (*Message, error) {
	msg := NewMessage()

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5.1. SCRAM Attributes

	clientRS, ok := clientFirsttMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(clientFirsttMsg.String())
	}
	serverRS, ok := serverFirsttMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(serverFirsttMsg.String())
	}
	if !strings.HasPrefix(serverRS, clientRS) {
		return nil, newErrInvalidMessage(clientFirsttMsg.String())
	}
	msg.SetRandomSequence(serverRS)

	// SaltedPassword

	salt, ok := serverFirsttMsg.Salt()
	if !ok {
		return nil, newErrInvalidMessage(serverFirsttMsg.String())
	}

	ic, ok := serverFirsttMsg.IterationCount()
	if !ok {
		return nil, newErrInvalidMessage(serverFirsttMsg.String())
	}

	saltedPassword, err := SaltedPassword(hashFunc, password, salt, ic)
	if err != nil {
		return nil, err
	}

	// ClientKey

	HMAC(hashFunc, saltedPassword, "Client Key")

	return msg, nil
}
