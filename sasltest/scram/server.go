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
	"github.com/cybergarage/go-sasl/sasl/cred"
	"github.com/cybergarage/go-sasl/sasl/scram"
	"github.com/cybergarage/go-sasl/sasltest"
)

const (
	Username = sasltest.Username
	Password = sasltest.Password
)

type Server struct {
	*scram.Server
}

func NewServer() (*Server, error) {
	var err error
	server := &Server{
		Server: nil,
	}
	server.Server, err = scram.NewServer()
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (server *Server) LookupCredential(q auth.Query) (cred.Credential, bool) {
	if q.Username() != Username {
		return nil, false
	}
	return cred.NewCredential(
		cred.WithCredentialUsername(q.Username()),
		cred.WithCredentialPassword(Password),
	), true
}
