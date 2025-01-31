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
	"fmt"

	"github.com/cybergarage/go-sasl/sasl/auth"
	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasl/scram"
)

// ServerContext represents a SCRAM server context.
type ServerContext struct {
	mechanism mech.Mechanism

	step int
	*scram.Server
}

// NewServerContext returns a new SCRAM server context.
func NewServerContext(m mech.Mechanism, opts ...scram.ServerOption) (*ServerContext, error) {
	server, err := scram.NewServer(opts...)
	if err != nil {
		return nil, err
	}
	return &ServerContext{
		mechanism: m,
		step:      0,
		Server:    server,
	}, nil
}

// Mechanism returns the mechanism.
func (ctx *ServerContext) Mechanism() mech.Mechanism {
	return ctx.mechanism
}

// Done returns true if the context is completed.
func (ctx *ServerContext) Done() bool {
	return ctx.step == 2
}

// Step returns the current step number. The step number is incremented by one after each call to Next.
func (ctx *ServerContext) Step() int {
	return ctx.step
}

// Next returns the next response.
func (ctx *ServerContext) Next(opts ...mech.Parameter) (mech.Response, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no message")
	}

	switch ctx.step {
	case 0:
		msg, err := scram.NewMessageFromWithHeader(opts[0])
		if err != nil {
			return nil, err
		}
		res, err := ctx.Server.FirstMessageFrom(msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	case 1:
		msg, err := scram.NewMessageFrom(opts[0])
		if err != nil {
			return nil, err
		}
		res, err := ctx.Server.FinalMessageFrom(msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	}

	return nil, fmt.Errorf("invalid step : %d", ctx.step)
}

// Dispose disposes the context.
func (ctx *ServerContext) Dispose() error {
	return nil
}

// Server represents a SCRAM mech.
type Server struct {
	scramType Type
	opts      []mech.Option
}

// NewSCRAM returns a new SCRAM mech.
func NewServerWithType(t Type) mech.Mechanism {
	return &Server{
		scramType: t,
		opts:      []mech.Option{},
	}
}

// Name returns the mechanism name.
func (server *Server) Name() string {
	return "SCRAM-" + server.scramType.String()
}

// Type returns the mechanism type.
func (server *Server) Type() mech.Type {
	return mech.Server
}

// SetOptions sets the mechanism options before starting.
func (server *Server) SetOptions(opts ...mech.Option) error {
	server.opts = opts
	return nil
}

// Start returns the initial context.
func (server *Server) Start(opts ...mech.Option) (mech.Context, error) {
	serverOpts := []scram.ServerOption{}

	switch server.scramType {
	case SHA1:
		serverOpts = append(serverOpts, scram.WithServerHashFunc(scram.HashSHA1()))
	case SHA256:
		serverOpts = append(serverOpts, scram.WithServerHashFunc(scram.HashSHA256()))
	case SHA512:
		serverOpts = append(serverOpts, scram.WithServerHashFunc(scram.HashSHA512()))
	default:
		return nil, fmt.Errorf("unknown SCRAM type : %d", server.scramType)
	}

	for _, opt := range append(server.opts, opts...) {
		switch v := opt.(type) {
		case auth.CredentialStore:
			serverOpts = append(serverOpts, scram.WithServerCredentialStore(v))
		case mech.RandomSequence:
			serverOpts = append(serverOpts, scram.WithServerRandomSequence(string(v)))
		case mech.HashFunc:
			serverOpts = append(serverOpts, scram.WithServerHashFunc(v))
		case mech.IterationCount:
			serverOpts = append(serverOpts, scram.WithServerIterationCount(int(v)))
		case mech.Salt:
			serverOpts = append(serverOpts, scram.WithServerSaltString(string(v)))
		default:
			return nil, fmt.Errorf("unknown option : %v", v)
		}
	}

	return NewServerContext(server, serverOpts...)
}
