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

	"github.com/cybergarage/go-sasl/sasl/mechanism"
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

// IsCompleted returns true if the context is completed.
func (ctx *ClientContext) IsCompleted() bool {
	return ctx.step == 3
}

// Step returns the current step number. The step number is incremented by one after each call to Next.
func (ctx *ClientContext) Step() int {
	return ctx.step
}

// Next returns the next response.
func (ctx *ClientContext) Next(opts ...mechanism.Parameter) (mechanism.Response, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no message")
	}

	msg, err := scram.NewMessageFrom(opts[0])
	if err != nil {
		return nil, err
	}

	switch ctx.step {
	case 0:
		res, err := ctx.Client.FirstMessage()
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	case 1:
		res, err := ctx.Client.FinalMessageFrom(msg)
		if err != nil {
			return nil, err
		}
		ctx.step++
		return res, nil
	case 2:
		err := ctx.Client.ValidateServerFinalMessage(msg)
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

// Client represents a SCRAM mechanism.
type Client struct {
	scramType Type
}

// NewSCRAM returns a new SCRAM mechanism.
func NewClientWithType(t Type) mechanism.Mechanism {
	return &Client{
		scramType: t,
	}
}

// Name returns the mechanism name.
func (client *Client) Name() string {
	return "SCRAM-" + client.scramType.String()
}

// Type returns the mechanism type.
func (client *Client) Type() mechanism.Type {
	return mechanism.Client
}

// Start returns the initial context.
func (client *Client) Start(opts ...mechanism.Option) (mechanism.Context, error) {
	clientOpts := []scram.ClientOption{}
	for _, opt := range opts {
		switch v := opt.(type) {
		case mechanism.Username:
			clientOpts = append(clientOpts, scram.WithClientUsername(string(v)))
		case mechanism.Password:
			clientOpts = append(clientOpts, scram.WithClientPassword(string(v)))
		}
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
