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

	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasl/scram"
)

// ClientContext represents a SCRAM client context.
type ClientContext struct {
	step int
	*scram.Client
}

// NewClientContext returns a new SCRAM client context.
func NewClientContext(opts ...scram.ClientOption) (*ClientContext, error) {
	client, err := scram.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &ClientContext{
		step:   0,
		Client: client,
	}, nil
}

// SetValue sets a value to the context.
func (ctx *ClientContext) SetValue(key string, value any) {
	ctx.Client.SetValue(key, value)
}

// Value returns a value from the context.
func (ctx *ClientContext) Value(key string) (any, bool) {
	return ctx.Client.Value(key)
}

// Done returns true if the context is completed.
func (ctx *ClientContext) Done() bool {
	return ctx.step == 3
}

// Step returns the current step number. The step number is incremented by one after each call to Next.
func (ctx *ClientContext) Step() int {
	return ctx.step
}

func newClientOptions(opts ...any) ([]scram.ClientOption, error) {
	clientOpts := []scram.ClientOption{}
	for _, opt := range opts {
		switch v := opt.(type) {
		case mech.Username:
			clientOpts = append(clientOpts, scram.WithClientUsername(string(v)))
		case mech.Password:
			clientOpts = append(clientOpts, scram.WithClientPassword(string(v)))
		case mech.Payload:
			clientOpts = append(clientOpts, scram.WithClientPayload(v))
		case mech.HashFunc:
			clientOpts = append(clientOpts, scram.WithClientHashFunc(v))
		case mech.AuthzID:
			clientOpts = append(clientOpts, scram.WithClientAuthzID(string(v)))
		case mech.RandomSequence:
			clientOpts = append(clientOpts, scram.WithClientRandomSequence(string(v)))
		case mech.Challenge:
			clientOpts = append(clientOpts, scram.WithClientChallenge(string(v)))
		}
	}
	return clientOpts, nil
}

// Next returns the next response.
func (ctx *ClientContext) Next(opts ...mech.Parameter) (mech.Response, error) {
	switch ctx.step {
	case 0:
		clientOpts, err := newClientOptions(opts...)
		if err != nil {
			return nil, err
		}
		if err := ctx.Client.SetOptions(clientOpts...); err != nil {
			return nil, err
		}
		res, err := ctx.Client.FirstMessage()
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	case 1:
		if len(opts) == 0 {
			return nil, fmt.Errorf("no client first message")
		}
		msg, err := scram.NewMessageFrom(opts[0])
		if err != nil {
			return nil, err
		}
		res, err := ctx.Client.FinalMessageFrom(msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	case 2:
		if len(opts) == 0 {
			return nil, fmt.Errorf("no client final message")
		}
		msg, err := scram.NewMessageFrom(opts[0])
		if err != nil {
			return nil, err
		}
		err = ctx.Client.ValidateServerFinalMessage(msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return nil, nil
	}

	return nil, fmt.Errorf("invalid step : %d", ctx.step)
}

// Dispose disposes the context.
func (ctx *ClientContext) Dispose() error {
	return nil
}

// Client represents a SCRAM mech.
type Client struct {
	scramType Type
}

// NewSCRAM returns a new SCRAM mech.
func NewClientWithType(t Type) mech.Mechanism {
	return &Client{
		scramType: t,
	}
}

// Name returns the mechanism name.
func (client *Client) Name() string {
	return "SCRAM-" + client.scramType.String()
}

// Type returns the mechanism type.
func (client *Client) Type() mech.Type {
	return mech.Client
}

// Start returns the initial context.
func (client *Client) Start(opts ...mech.Option) (mech.Context, error) {
	clientOpts, err := newClientOptions(opts...)
	if err != nil {
		return nil, err
	}
	switch client.scramType {
	case SHA1:
		clientOpts = append(clientOpts, scram.WithClientHashFunc(scram.HashSHA1()))
		return NewClientContext(clientOpts...)
	case SHA256:
		clientOpts = append(clientOpts, scram.WithClientHashFunc(scram.HashSHA256()))
		return NewClientContext(clientOpts...)
	case SHA512:
		clientOpts = append(clientOpts, scram.WithClientHashFunc(scram.HashSHA512()))
		return NewClientContext(clientOpts...)
	}
	return nil, fmt.Errorf("unknown SCRAM type : %d", client.scramType)
}
