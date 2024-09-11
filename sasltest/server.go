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

package sasltest

import (
	"github.com/cybergarage/go-sasl/sasl"
	"github.com/cybergarage/go-sasl/sasl/cred"
)

type Server struct {
	*sasl.Server
}

func NewServer() *Server {
	server := &Server{
		Server: sasl.NewServer(),
	}
	server.AddAuthenticator(server)
	return server
}

func (server *Server) HasCredential(q *cred.Query, opts ...cred.AuthenticatorOption) (*cred.Credential, bool) {
	cred := cred.NewCredential(
		cred.WithCredentialUsername(q.Username()),
		cred.WithCredentialPassword(Password),
	)
	return cred, true
}
