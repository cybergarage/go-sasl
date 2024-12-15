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

package anonymous

import (
	"fmt"

	"github.com/cybergarage/go-sasl/sasl/mech"
)

// ClientContext represents a PLAIN client context.
type ClientContext struct {
	mechanism mech.Mechanism

	mech.Store
	msg  string
	step int
}

// NewClientContext returns a new PLAIN client context.
func NewClientContext(m mech.Mechanism, opts ...mech.Option) (*ClientContext, error) {
	ctx := &ClientContext{
		mechanism: m,
		Store:     mech.NewStore(),
		msg:       "",
		step:      0,
	}

	if err := ctx.setOptions(opts...); err != nil {
		return nil, err
	}

	return ctx, nil
}

func (ctx *ClientContext) setOptions(opts ...any) error {
	for _, opt := range opts {
		switch v := opt.(type) {
		case mech.Email:
			ctx.msg = string(v)
		case mech.Token:
			ctx.msg = string(v)
		}
	}
	return nil
}

// Mechanism returns the mechanism.
func (ctx *ClientContext) Mechanism() mech.Mechanism {
	return ctx.mechanism
}

// Done returns true if the context is completed.
func (ctx *ClientContext) Done() bool {
	return ctx.step == 1
}

// Step returns the current step number. The step number is incremented by one after each call to Next.
func (ctx *ClientContext) Step() int {
	return ctx.step
}

// Next returns the next response.
func (ctx *ClientContext) Next(opts ...mech.Parameter) (mech.Response, error) {
	switch ctx.step {
	case 0:
		if err := ctx.setOptions(opts...); err != nil {
			return nil, err
		}
		msg, err := NewMessageFrom(ctx.msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return msg, nil
	}
	return nil, fmt.Errorf("invalid step : %d", ctx.step)
}

// Dispose disposes the context.
func (ctx *ClientContext) Dispose() error {
	return nil
}

// Client represents a PLAIN mech.
type Client struct {
	opts []mech.Option
}

// NewClient returns a new PLAIN client.
func NewClient() *Client {
	return &Client{
		opts: []mech.Option{},
	}
}

// Name returns the mechanism name.
func (client *Client) Name() string {
	return Type
}

// Type returns the mechanism type.
func (client *Client) Type() mech.Type {
	return mech.Client
}

// SetOptions sets the mechanism options before starting.
func (client *Client) SetOptions(opts ...mech.Option) error {
	client.opts = opts
	return nil
}

// Start returns the initial context.
func (client *Client) Start(opts ...mech.Option) (mech.Context, error) {
	ctxOpts := append(client.opts, opts...)
	return NewClientContext(client, ctxOpts...)
}
