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
	"github.com/cybergarage/go-sasl/sasl/util/rand"
)

// Server represents a SCRAM server.
type Server struct {
	challenge string
	authzID   string
	username  string
}

// ServerOption represents a server option.
type ServerOption func(*Server) error

// NewServer returns a new SCRAM server.
func NewServer(opts ...ServerOption) (*Server, error) {
	srv := &Server{
		challenge: "",
		authzID:   "",
		username:  "",
	}
	for _, opt := range opts {
		err := opt(srv)
		if err != nil {
			return nil, err
		}
	}
	return srv, nil
}

// FirstMessageFrom returns a new server first message from the specified client message.
func (server *Server) FirstMessageFrom(clientMsg *Message) (*Message, error) {
	msg := NewMessage()

	// authzid: authorization ID

	authzID, ok := clientMsg.AuthorizationID()
	if ok {
		server.authzID = string(authzID)
	}

	// u: username

	u, ok := clientMsg.Username()
	if ok {
		server.username = string(u)
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

	msg.SetIterationCount(defaultIterationCount)

	return msg, nil
}

// FinalMessageFrom returns a new server final message from the specified client final message.
func (server *Server) FinalMessageFrom(clientFinaltMsg *Message) (*Message, error) {
	msg := NewMessage()
	return msg, nil
}
