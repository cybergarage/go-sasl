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

	"github.com/cybergarage/go-sasl/sasl/cred"
	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasl/mech/plugins"
)

// ServerContext represents a PLAIN server context.
type ServerContext struct {
	*plugins.Context
	step int
	*cred.CredentialStore
}

// NewServerContext returns a new PLAIN server context.
func NewServerContext(opts ...mech.Option) (*ServerContext, error) {
	ctx := &ServerContext{
		Context:         plugins.NewContext(),
		step:            0,
		CredentialStore: cred.NewCredentialStore(),
	}

	for _, opt := range opts {
		switch v := opt.(type) {
		case mech.Authenticators:
			ctx.SetAuthenticators(v)
		}
	}

	return ctx, nil
}

// IsCompleted returns true if the context is completed.
func (ctx *ServerContext) IsCompleted() bool {
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
		cred := cred.NewCredential(
			cred.WithGroup(msg.Authzid()),
			cred.WithUsername(msg.Authcid()),
			cred.WithPassword(msg.Passwd()),
		)
		storeCred, err := ctx.HasCredential(cred.Username())
		if err != nil {
			return nil, fmt.Errorf("no credential")
		}
		if !storeCred.Authorize(cred) {
			return nil, fmt.Errorf("no credential")
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
}

func NewServer() mech.Mechanism {
	return &Server{}
}

// Name returns the mechanism name.
func (server *Server) Name() string {
	return Type
}

// Type returns the mechanism type.
func (server *Server) Type() mech.Type {
	return mech.Server
}

// Start returns the initial context.
func (server *Server) Start(opts ...mech.Option) (mech.Context, error) {
	return NewServerContext(opts...)
}
