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

import (
	"github.com/cybergarage/go-sasl/sasl/plugins/plain"
	"github.com/cybergarage/go-sasl/sasl/plugins/scram"
)

// Client represents a SASL client.
type Client struct {
	*Provider
}

// NewClient returns a new client.
func NewClient() *Client {
	client := &Client{
		Provider: NewProvider(),
	}
	client.loadDefaultPlugins()
	return client
}

func (client *Client) loadDefaultPlugins() {
	client.AddMechanism(plain.NewClient())
	for _, t := range scram.SCRAMTypes() {
		client.AddMechanism(scram.NewClientWithType(t))
	}
}
