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

package plain

import (
	"fmt"
	"net"
	"slices"

	"github.com/cybergarage/go-sasl/sasl/auth"
	"github.com/cybergarage/go-sasl/sasl/mech"
)

// ServerContext represents a PLAIN server context.
type ServerContext struct {
	mechanism mech.Mechanism
	mech.Store
	step int
	auth.Manager
	net.Conn
}

// NewServerContext returns a new PLAIN server context.
func NewServerContext(m mech.Mechanism, opts ...mech.Option) (*ServerContext, error) {
	ctx := &ServerContext{
		mechanism: m,
		Store:     mech.NewStore(),
		step:      0,
		Manager:   auth.NewManager(),
		Conn:      nil,
	}

	for _, opt := range opts {
		switch v := opt.(type) {
		case auth.Manager:
			ctx.Manager = v
		case net.Conn:
			ctx.Conn = v
		}
	}

	return ctx, nil
}

// Mechanism returns the mechanism.
func (ctx *ServerContext) Mechanism() mech.Mechanism {
	return ctx.mechanism
}

// Done returns true if the context is completed.
func (ctx *ServerContext) Done() bool {
	return ctx.step == 1
}

// Step returns the current step number. The step number is incremented by one after each call to Next.
func (ctx *ServerContext) Step() int {
	return ctx.step
}

// Next returns the next response.
func (ctx *ServerContext) Next(opts ...mech.Parameter) (mech.Response, error) {
	switch ctx.step {
	case 0:
		if len(opts) == 0 {
			return nil, fmt.Errorf("no message")
		}
		msg, err := NewMessageFrom(opts[0])
		if err != nil {
			return nil, err
		}

		q, err := auth.NewQuery(
			auth.WithQueryGroup(msg.Authzid()),
			auth.WithQueryUsername(msg.Authcid()),
			auth.WithQueryPassword(msg.Passwd()),
		)
		if err != nil {
			return nil, err
		}

		ok, err := ctx.VerifyCredential(ctx.Conn, q)
		if !ok {
			return nil, err
		}
		ctx.step++
		return nil, nil
	}

	return nil, fmt.Errorf("invalid step : %d", ctx.step)
}

// Dispose disposes the context.
func (ctx *ServerContext) Dispose() error {
	return nil
}

// Server represents a PLAIN mech.
type Server struct {
	opts []mech.Option
}

func NewServer() mech.Mechanism {
	return &Server{
		opts: []mech.Option{},
	}
}

// Name returns the mechanism name.
func (server *Server) Name() string {
	return Type
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
	return NewServerContext(server, slices.Concat(server.opts, opts)...)
}
