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
	"github.com/cybergarage/go-sasl/sasl/auth"
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Server represents a SCRAM server.
type Server struct {
	*auth.AuthManager
	challenge      string
	authzID        string
	iterationCount int
}

// ServerOption represents a server option.
type ServerOption func(*Server) error

// NewServer returns a new SCRAM server.
func NewServer(opts ...ServerOption) (*Server, error) {
	srv := &Server{
		AuthManager:    auth.NewAuthManager(),
		challenge:      "",
		authzID:        "",
		iterationCount: defaultIterationCount,
	}
	for _, opt := range opts {
		err := opt(srv)
		if err != nil {
			return nil, err
		}
	}
	return srv, nil
}

// WithIterationCount returns an option to set the iteration count.
func WithIterationCount(iterationCount int) ServerOption {
	return func(server *Server) error {
		server.iterationCount = iterationCount
		return nil
	}
}

// FirstMessageFrom returns a new server first message from the specified client message.
func (server *Server) FirstMessageFrom(clientMsg *Message) (*Message, error) {
	msg := NewMessage()

	// authzid: authorization ID
	//  This is an optional attribute, and is part of the GS2 [RFC5801] bridge between the GSS-API and SASL
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

	err := server.HasCredential(server.authzID)
	if err != nil {
		return nil, ErrAuthorization
	}

	// r: random sequence

	cr, ok := clientMsg.RandomSequence()
	if !ok {
		return nil, newErrInvalidMessage(clientMsg.String())
	}
	r, err := rand.NewRandomSequence(additionalRandomSequenceLength)
	if err != nil {
		return nil, err
	}
	sr := string(cr) + string(r)
	msg.SetRandomSequence(sr)

	salt, err := rand.NewSalt(defaultSaltLength)
	if err != nil {
		return nil, err
	}
	msg.SetSalt(salt)

	msg.SetIterationCount(server.iterationCount)

	return msg, nil
}

// FinalMessageFrom returns a new server final message from the specified client final message.
func (server *Server) FinalMessageFrom(clientFinaltMsg *Message) (*Message, error) {
	msg := NewMessage()
	return msg, nil
}
