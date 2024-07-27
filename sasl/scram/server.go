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
	"crypto/hmac"
	"encoding/base64"

	"github.com/cybergarage/go-sasl/sasl/auth"
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Server represents a SCRAM server.
type Server struct {
	*auth.AuthManager
	challenge      string
	authzID        string
	randomSequence string
	iterationCount int
	salt           []byte
	hashFunc       HashFunc
	clientFirstMsg *Message
	serverFirstMsg *Message
}

// ServerOption represents a server option.
type ServerOption func(*Server) error

// NewServer returns a new SCRAM server.
func NewServer(opts ...ServerOption) (*Server, error) {
	srv := &Server{
		AuthManager:    auth.NewAuthManager(),
		challenge:      "",
		authzID:        "",
		randomSequence: "",
		hashFunc:       HashSHA256(),
		iterationCount: defaultIterationCount,
		salt:           nil,
		clientFirstMsg: nil,
		serverFirstMsg: nil,
	}
	rs, err := rand.NewRandomSequence(additionalRandomSequenceLength)
	if err != nil {
		return nil, err
	}
	srv.randomSequence = string(rs)

	err = srv.SetOption(opts...)
	if err != nil {
		return nil, err
	}

	return srv, nil
}

// WithServerIterationCount returns a server option to set the iteration count.
func WithServerIterationCount(iterationCount int) ServerOption {
	return func(server *Server) error {
		server.iterationCount = iterationCount
		return nil
	}
}

// WithServerRandomSequence returns a server option to set the random sequence.
func WithServerRandomSequence(randomSequence string) ServerOption {
	return func(server *Server) error {
		server.randomSequence = randomSequence
		return nil
	}
}

// WithServerHashFunc returns a server option to set the hash function.
func WithServerHashFunc(hashFunc HashFunc) ServerOption {
	return func(server *Server) error {
		server.hashFunc = hashFunc
		return nil
	}
}

// WithServerSaltString returns a server option to set the salt.
func WithServerSaltString(salt string) ServerOption {
	return func(server *Server) error {
		decordedSalt, err := base64.StdEncoding.DecodeString(salt)
		if err != nil {
			return err
		}
		server.salt = decordedSalt
		return nil
	}
}

// SetOption sets the specified options.
func (server *Server) SetOption(opts ...ServerOption) error {
	for _, opt := range opts {
		err := opt(server)
		if err != nil {
			return err
		}
	}
	return nil
}

// FirstMessageFrom returns a new server first message from the specified client message.
func (server *Server) FirstMessageFrom(clientMsg *Message) (*Message, error) {
	msg := NewMessage()

	// authzid: authorization ID
	//  This is a server optional attribute, and is part of the GS2 [RFC5801] bridge between the GSS-API and SASL
	authzID, ok := clientMsg.AuthorizationID()
	if ok {
		server.authzID = string(authzID)
	} else {
		// u: username
		// If the "a" attribute is not specified (which would normally be the case),
		// this username is also the identity that will be associated with the connection subsequent to
		// authentication and authorization.
		u, ok := clientMsg.Username()
		if ok {
			server.authzID = string(u)
		}
	}

	//  If the preparation of the username fails or results in an empty string,
	// the client SHOULD abort the authentication exchange

	if len(server.authzID) == 0 {
		return nil, ErrAuthorization
	}

	_, err := server.HasCredential(server.authzID)
	if err != nil {
		return nil, ErrAuthorization
	}

	// r: random sequence

	cr, ok := clientMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(clientMsg.String())
	}
	sr := string(cr) + string(server.randomSequence)
	msg.SetRandomSequence(sr)

	// s: salt

	if len(server.salt) == 0 {
		salt, err := rand.NewSalt(defaultSaltLength)
		if err != nil {
			return nil, err
		}
		server.salt = salt
	}
	msg.SetSaltBytes(server.salt)

	// i: iteration count

	msg.SetIterationCount(server.iterationCount)

	server.clientFirstMsg = clientMsg
	server.serverFirstMsg = msg

	return msg, nil
}

// FinalMessageFrom returns a new server final message from the specified client final message.
func (server *Server) FinalMessageFrom(clienttMsg *Message) (*Message, error) {
	if server.clientFirstMsg == nil || server.serverFirstMsg == nil {
		return nil, newErrInvalidMessage("First message is not set")
	}

	// The server MUST verify that the nonce sent by the client in the second message is
	// the same as the one sent by the server in its first message.

	clientRS, ok := clienttMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(clienttMsg.String())
	}
	serverRS, ok := server.serverFirstMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(server.serverFirstMsg.String())
	}
	if clientRS != serverRS {
		return nil, newErrInvalidMessage(server.serverFirstMsg.String())
	}

	storedCred, err := server.HasCredential(server.authzID)
	if err != nil {
		return nil, ErrAuthorization
	}

	// AuthMessage := client-first-message-bare + "," +
	//                server-first-message + "," +
	//                client-final-message-without-proof

	authMsg := AuthMessage(server.clientFirstMsg.String(), server.serverFirstMsg.String(), clienttMsg.StringWithoutProof())

	// ClientSignature := HMAC(StoredKey, AuthMessage)

	clientSignature := HMAC(server.hashFunc, []byte(storedCred.Password()), []byte(authMsg))

	clientProof, ok := clienttMsg.ClientProof()
	if !ok {
		return nil, newErrInvalidMessage(clienttMsg.String())
	}

	clientKey := XOR(clientProof, clientSignature)
	storedKey := H(server.hashFunc, clientKey)

	if !hmac.Equal([]byte(storedKey), []byte(storedCred.Password())) {
		return nil, ErrAuthorization
	}

	// SaltedPassword := Hi(Normalize(password), salt, i)
	saltedPassword, err := SaltedPassword(server.hashFunc, storedCred.Password(), server.salt, server.iterationCount)
	if err != nil {
		return nil, err
	}

	// ServerKey := HMAC(SaltedPassword, "Server Key")
	serverKey := HMAC(server.hashFunc, saltedPassword, []byte("Server Key"))
	//  ServerSignature := HMAC(ServerKey, AuthMessage)
	serverSignature := HMAC(server.hashFunc, serverKey, []byte(authMsg))

	msg := NewMessage()
	msg.SetServerSignature(serverSignature)

	return msg, nil
}
