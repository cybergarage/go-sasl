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

	"github.com/cybergarage/go-sasl/sasl/mech"
)

// ClientContext represents a PLAIN client context.
type ClientContext struct {
	username string
	password string
	step     int
}

// NewClientContext returns a new PLAIN client context.
func NewClientContext(opts ...mech.Option) (*ClientContext, error) {
	ctx := &ClientContext{
		username: "",
		password: "",
		step:     0,
	}

	for _, opt := range opts {
		switch v := opt.(type) {
		case mech.Username:
			ctx.username = string(v)
		case mech.Password:
			ctx.password = string(v)
		}
	}

	return ctx, nil
}

// IsCompleted returns true if the context is completed.
func (ctx *ClientContext) IsCompleted() bool {
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
		ctx.step++
		return nil, nil
	}
	return nil, fmt.Errorf("invalid step : %d", ctx.step)
}

// Dispose disposes the context.
func (ctx *ClientContext) Dispose() error {
	return nil
}

// Client represents a PLAIN mech.
type Client struct {
}

// Name returns the mechanism name.
func (client *Client) Name() string {
	return Type
}

// Type returns the mechanism type.
func (client *Client) Type() mech.Type {
	return mech.Client
}

// Start returns the initial context.
func (client *Client) Start(opts ...mech.Option) (mech.Context, error) {
	return NewClientContext(opts...)
}
