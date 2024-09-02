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
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/cybergarage/go-sasl/sasl/gss"
	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasl/util"
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Client is a SCRAM client.
type Client struct {
	mech.Store
	authzID        string
	username       string
	password       string
	hashFunc       HashFunc
	challenge      string
	clientFirstMsg *Message
	clientFinalMsg *Message
	serverFirstMsg *Message
	randomSequence string
}

// ClientOption represents a client option function.
type ClientOption func(*Client) error

// NewClient returns a new SCRAM client with options.
func NewClient(opts ...ClientOption) (*Client, error) {
	client := &Client{
		Store:          mech.NewStore(),
		authzID:        "",
		username:       "",
		password:       "",
		hashFunc:       HashSHA256(),
		challenge:      "",
		randomSequence: "",
		clientFirstMsg: nil,
		clientFinalMsg: nil,
		serverFirstMsg: nil,
	}

	seq, err := rand.NewRandomSequence(initialRandomSequenceLength)
	if err != nil {
		return nil, err
	}
	client.randomSequence = string(seq)

	err = client.SetOptions(opts...)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// WithClientAuthzID returns a client option to set the authorization ID.
func WithClientAuthzID(authzID string) ClientOption {
	return func(client *Client) error {
		client.authzID = authzID
		return nil
	}
}

// WithClientUsername returns a client option to set the username.
func WithClientUsername(username string) ClientOption {
	return func(client *Client) error {
		client.username = username
		return nil
	}
}

// WithClientPassword returns a client option to set the password.
func WithClientPassword(password string) ClientOption {
	return func(client *Client) error {
		client.password = password
		return nil
	}
}

// WithClientHashFunc returns a client option to set the hash function.
func WithClientHashFunc(hashFunc HashFunc) ClientOption {
	return func(client *Client) error {
		client.hashFunc = hashFunc
		return nil
	}
}

// WithClientRandomSequence returns a client option to set the random sequence.
func WithClientRandomSequence(randomSequence string) ClientOption {
	return func(client *Client) error {
		client.randomSequence = randomSequence
		return nil
	}
}

// WithClientChallenge returns a client option to set the challenge.
func WithClientChallenge(challenge string) ClientOption {
	return func(client *Client) error {
		client.challenge = challenge
		return nil
	}
}

func WithClientPayload(payload mech.Payload) ClientOption {
	return func(client *Client) error {
		msg, err := NewMessageFromString(string(payload))
		if err != nil {
			return err
		}
		opts, err := newClientOptionsFromMessage(msg)
		if err != nil {
			return err
		}
		return client.SetOptions(opts...)
	}
}

func newClientOptionsFromMessage(msg *Message) ([]ClientOption, error) {
	opts := []ClientOption{}

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5. SCRAM Authentication Exchange
	cbFlag := msg.CBFlag()
	if !cbFlag.IsValid() {
		return opts, newErrInvalidMessage(msg.String())
	}

	// 5.1. SCRAM Attributes
	authzID, ok := msg.AuthorizationID()
	if ok {
		opts = append(opts, WithClientAuthzID(util.DecodeName(authzID)))
	}
	user, ok := msg.Username()
	if ok {
		opts = append(opts, WithClientUsername(util.DecodeName(user)))
	}

	return opts, nil
}

// NewClientFromPayload returns a new SCRAM client from the specified payload.
func NewClientFromPayload(payload string) (*Client, error) {
	msg, err := NewMessageFromString(payload)
	if err != nil {
		return nil, err
	}
	return newClientWithMessage(msg)
}

// NewClientFromPayloadWithHeader returns a new SCRAM client from the specified payload with the header.
func NewClientFromPayloadWithHeader(payload string) (*Client, error) {
	msg, err := NewMessageFromStringWithHeader(payload)
	if err != nil {
		return nil, err
	}
	return newClientWithMessage(msg)
}

func newClientWithMessage(msg *Message) (*Client, error) {
	opts, err := newClientOptionsFromMessage(msg)
	if err != nil {
		return nil, err
	}
	return NewClient(opts...)
}

// SetOptions sets the client options.
func (client *Client) SetOptions(opts ...ClientOption) error {
	for _, opt := range opts {
		err := opt(client)
		if err != nil {
			return err
		}
	}
	return nil
}

// HashFunc returns the hash function.
func (client *Client) HashFunc() HashFunc {
	return client.hashFunc
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
		client.SetValue(UsernameID, client.username)
	}

	// r: random sequence

	msg.SetRandomSequence(client.randomSequence)
	client.SetValue(RandomSequenceID, client.randomSequence)

	client.clientFirstMsg = msg

	return msg, nil
}

// FinalMessageFrom returns the final message from the specified server first message.
func (client *Client) FinalMessageFrom(serverFirstMsg *Message) (*Message, error) {
	if serverFirstMsg == nil {
		return nil, newErrInvalidMessage("Server first message is not set")
	}

	if client.clientFirstMsg == nil {
		return nil, newErrInvalidMessage("First message is not set")
	}

	client.serverFirstMsg = serverFirstMsg

	msg := NewMessage()

	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// 5.1. SCRAM Attributes

	//  The base64-encoded GS2 header and channel binding data.

	c := base64.StdEncoding.EncodeToString([]byte(client.clientFirstMsg.Header.String()))
	msg.SetChannelBindingData(c)

	// The client MUST verify that the initial part of the nonce used in
	// subsequent messages is the same as the nonce it initially specified.

	clientRS, ok := client.clientFirstMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(client.clientFirstMsg.String())
	}
	serverRS, ok := serverFirstMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}
	if !strings.HasPrefix(serverRS, clientRS) {
		return nil, newErrInvalidMessage(client.clientFirstMsg.String())
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

	// SaltedPassword := Hi(Normalize(password), salt, i)

	salt, ok := serverFirstMsg.Salt()
	if !ok {
		return nil, newErrInvalidMessage(serverFirstMsg.String())
	}

	saltedPassword, err := SaltedPassword(client.hashFunc, client.password, salt, ic)
	if err != nil {
		return nil, err
	}
	client.SetValue(SaltedPasswordID, saltedPassword)

	// ClientKey := HMAC(SaltedPassword, "Client Key")

	clientKey := ClientKey(client.hashFunc, saltedPassword)
	client.SetValue(ClientKeyID, clientKey)

	//  StoredKey := H(ClientKey)

	storedKey := H(client.hashFunc, clientKey)
	client.SetValue(StoredKeyID, storedKey)

	// AuthMessage := client-first-message-bare + "," +
	//                server-first-message + "," +
	//                client-final-message-without-proof

	authMsg := AuthMessage(client.clientFirstMsg.StringWithoutHeader(), serverFirstMsg.String(), msg.StringWithoutProof())
	client.SetValue(AuthMessageID, authMsg)

	// ClientSignature := HMAC(StoredKey, AuthMessage)

	clientSignature := HMAC(client.hashFunc, storedKey, []byte(authMsg))
	client.SetValue(ClientSignatureID, clientSignature)

	// ClientProof := ClientKey XOR ClientSignature

	clientProof := XOR(clientKey, clientSignature)
	msg.SetClientProof(clientProof)
	client.SetValue(ClientProofID, clientProof)

	client.clientFinalMsg = msg

	return msg, nil
}

// ValidateServerFinalMessage validates the final message from the specified server final message.
func (client *Client) ValidateServerFinalMessage(serverFinalMsg *Message) error {
	if serverFinalMsg == nil {
		return newErrInvalidMessage("server final message is not set")
	}

	if client.clientFirstMsg == nil {
		return newErrInvalidMessage("client first message is not set")
	}

	if client.clientFirstMsg == nil {
		return newErrInvalidMessage("client final message is not set")
	}

	if client.serverFirstMsg == nil {
		return newErrInvalidMessage("server first message is not set")
	}

	receivedServerSignature, ok := serverFinalMsg.ServerSignature()
	if !ok {
		return newErrInvalidMessage(serverFinalMsg.String())
	}

	// SaltedPassword := Hi(Normalize(password), salt, i)

	ic, ok := client.serverFirstMsg.IterationCount()
	if !ok {
		return newErrInvalidMessage(client.serverFirstMsg.String())
	}

	salt, ok := client.serverFirstMsg.Salt()
	if !ok {
		return newErrInvalidMessage(client.serverFirstMsg.String())
	}

	saltedPassword, err := SaltedPassword(client.hashFunc, client.password, salt, ic)
	if err != nil {
		return err
	}
	client.SetValue(SaltedPasswordID, saltedPassword)

	// AuthMessage := client-first-message-bare + "," +
	//                server-first-message + "," +
	//                client-final-message-without-proof

	authMsg := AuthMessage(client.clientFirstMsg.StringWithoutHeader(), client.serverFirstMsg.String(), client.clientFinalMsg.StringWithoutProof())
	client.SetValue(AuthMessageID, authMsg)

	// ServerKey := HMAC(SaltedPassword, "Server Key")

	serverKey := HMAC(client.hashFunc, saltedPassword, []byte("Server Key"))
	client.SetValue(ServerKeyID, serverKey)

	// ServerSignature := HMAC(ServerKey, AuthMessage)
	serverSignature := HMAC(client.hashFunc, serverKey, []byte(authMsg))
	client.SetValue(ServerSignatureID, serverSignature)

	if !bytes.Equal(serverSignature, receivedServerSignature) {
		return newErrInvalidMessage(serverFinalMsg.String())
	}

	return nil
}
