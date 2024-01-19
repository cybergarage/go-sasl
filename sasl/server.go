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

package sasl

// Server represents a SASL server.
type Server struct {
	Mechanisms []*Mechanism
}

// NewServer returns a new SASL server.
func NewServer() *Server {
	server := &Server{
		Mechanisms: []*Mechanism{},
	}
	return server
}

// AddMechanism adds a mechanism to the server.
func (server *Server) AddMechanism(mech *Mechanism) {
	server.Mechanisms = append(server.Mechanisms, mech)
}
