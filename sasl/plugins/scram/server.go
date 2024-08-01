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
	"github.com/cybergarage/go-sasl/sasl/mechanism"
	"github.com/cybergarage/go-sasl/sasl/scram"
)

// ServerContext represents a SCRAM server context.
type ServerContext struct {
	*scram.Server
}

// NewServerContext returns a new SCRAM server context.
func NewServerContext(opts ...scram.ServerOption) (*ServerContext, error) {
	server, err := scram.NewServer(opts...)
	if err != nil {
		return nil, err
	}
	return &ServerContext{
		Server: server,
	}, nil
}

// Next returns the next response.
func (ctx *ServerContext) Next(...mechanism.Parameter) (mechanism.Response, error) {
	return nil, nil
}

// Dispose disposes the context.
func (ctx *ServerContext) Dispose() error {
	return nil
}

// Server represents a SCRAM mechanism.
type Server struct {
	typ SCRAMType
}

// NewSCRAM returns a new PLAIN mechanism.
func NewServerWithType(t SCRAMType) mechanism.Mechanism {
	return &Server{
		typ: t,
	}
}

// Name returns the mechanism name.
func (server *Server) Name() string {
	return "SCRAM-" + server.typ.String()
}

// Type returns the SCRAM type.
func (server *Server) Type() SCRAMType {
	return server.typ
}

// Start returns the initial context.
func (server *Server) Start(...mechanism.Parameter) (mechanism.Context, error) {
	switch server.typ {
	case SCRAMTypeSHA1:
		return NewServerContext(scram.WithServerHashFunc(scram.HashSHA1()))
	case SCRAMTypeSHA256:
		return NewServerContext(scram.WithServerHashFunc(scram.HashSHA256()))
	case SCRAMTypeSHA512:
		return NewServerContext(scram.WithServerHashFunc(scram.HashSHA512()))
	}
	return nil, nil
}
