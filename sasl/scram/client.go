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
	"strings"

	"github.com/cybergarage/go-sasl/sasl/gss"
	"github.com/cybergarage/go-sasl/sasl/util"
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Client is a SCRAM client.
type Client struct {
	authzID   string
	username  string
	password  string
	hashFunc  HashFunc
	challenge string
	firstMsg  *Message
}

// ClientOption represents a client option function.
type ClientOption func(*Client) error

// NewClient returns a new SCRAM client with options.
func NewClient(opts ...ClientOption) (*Client, error) {
	client := &Client{
		authzID:   "",
		username:  "",
		password:  "",
		hashFunc:  HashSHA256(),
		challenge: "",
		firstMsg:  nil,
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
func WithAuthzID(authzID string) ClientOption {
	return func(client *Client) error {
		client.authzID = authzID
		return nil
	}
}

// WithUsername returns an option to set the username.
func WithUsername(username string) ClientOption {
	return func(client *Client) error {
		client.username = username
		return nil
	}
}

// WithPassword returns an option to set the password.
func WithPassword(password string) ClientOption {
	return func(client *Client) error {
		client.password = password
		return nil
	}
}

// WithHashFunc returns an option to set the hash function.
func WithHashFunc(hashFunc HashFunc) ClientOption {
	return func(client *Client) error {
		client.hashFunc = hashFunc
		return nil
	}
}

// WithChallenge returns an option to set the challenge.
func WithChallenge(challenge string) ClientOption {
	return func(client *Client) error {
		client.challenge = challenge
		return nil
	}
}

// NewClientFromMessage returns a new SCRAM client from the specified message.
func NewClientFromMessage(msgStr string) (*Client, error) {
	msg, err := NewMessageFromString(msgStr)
	if err != nil {
		return nil, err
	}
	return newClientWithMessage(msg)
}

// NewClientFromMessageWithHeader returns a new SCRAM client from the specified message with the GS2 header.
func NewClientFromMessageWithHeader(msgStr string) (*Client, error) {
	msg, err := NewMessageFromStringWithHeader(msgStr)
	if err != nil {
		return nil, err
	}
	return newClientWithMessage(msg)
}

func newClientWithMessage(msg *Message) (*Client, error) {
	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5. SCRAM Authentication Exchange
	cbFlag := msg.CBFlag()
	if !cbFlag.IsValid() {
		return nil, newErrInvalidMessage(msg.String())
	}

	opts := []ClientOption{}

	// 5.1. SCRAM Attributes
	authzID, ok := msg.AuthorizationID()
	if ok {
		opts = append(opts, WithAuthzID(util.DecodeName(authzID)))
	}
	user, ok := msg.Username()
	if ok {
		opts = append(opts, WithUsername(util.DecodeName(user)))
	}
	return NewClient(opts...)
}

// FirstMessage returns the first message.
func (client *Client) FirstMessage() (*Message, error) {
	msg := NewMessage(WithHeader(gss.NewHeader()))

	if 0 < len(client.authzID) {
		msg.SetAuthzID(util.EncodeName(client.authzID))
	}

	// GS2 Header

	msg.SetCBFlag(gss.ClientDoesNotSupportCBSFlag)
	if 0 < len(client.authzID) {
		msg.SetAuthzID(client.authzID)
	}

	// n: username

	if 0 < len(client.username) {
		msg.SetUsername(util.EncodeName(client.username))
	}

	// r: random sequence

	seq, err := rand.NewRandomSequence(initialRandomSequenceLength)
	if err != nil {
		return nil, err
	}
	msg.SetRandomSequence(string(seq))

	client.firstMsg = msg

	return msg, nil
}

// FinalMessageFrom returns the final message from the specified server first message.
func (client *Client) FinalMessageFrom(serverFirstMsg *Message) (*Message, error) {
	if client.firstMsg == nil {
		return nil, newErrInvalidMessage("First message is not set")
	}

	msg := NewMessage()

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5.1. SCRAM Attributes

	// The client MUST verify that the initial part of the nonce used in
	// subsequent messages is the same as the nonce it initially specified.

	clientRS, ok := client.firstMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(client.firstMsg.String())
	}
	serverRS, ok := serverFirstMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}
	if !strings.HasPrefix(serverRS, clientRS) {
		return nil, newErrInvalidMessage(client.firstMsg.String())
	}
	msg.SetRandomSequence(serverRS)

	// For the SCRAM-SHA-1/SCRAM-SHA-1-PLUS SASL mechanism,
	// servers SHOULD announce a hash iteration-count of at least 4096.

	ic, ok := serverFirstMsg.IterationCount()
	if !ok {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}

	if ic < minimumIterationCount {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}

	//  The base64-encoded GS2 header and channel binding data.

	c := base64.StdEncoding.EncodeToString([]byte(client.firstMsg.Header.String()))
	msg.SetChannelBindingData(c)

	// SaltedPassword

	salt, ok := serverFirstMsg.Salt()
	if !ok {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}

	saltedPassword, err := SaltedPassword(client.hashFunc, client.password, salt, ic)
	if err != nil {
		return nil, err
	}

	// ClientKey

	HMAC(client.hashFunc, saltedPassword, "Client Key")

	return msg, nil
}
