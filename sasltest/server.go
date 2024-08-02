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
	"github.com/cybergarage/go-sasl/sasl/auth"
)

type Server struct {
	*sasl.Server
}

func NewServer() (*Server, error) {
	server := &Server{
		Server: nil,
	}
	server.Server = sasl.NewServer()
	server.AddAuthenticator(server)
	return server, nil
}

func (server *Server) HasCredential(username string) (*auth.Credential, bool) {
	cred := auth.NewCredential(
		auth.WithUsername(username),
		auth.WithPassword(Paassword),
	)
	return cred, true
}
