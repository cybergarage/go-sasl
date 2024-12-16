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
	"github.com/cybergarage/go-sasl/sasl/auth"
	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasl/mech/plugins/anonymous"
	"github.com/cybergarage/go-sasl/sasl/mech/plugins/plain"
	"github.com/cybergarage/go-sasl/sasl/mech/plugins/scram"
)

// server represents a SASL server.
type server struct {
	*Provider
	auth.Manager
}

// NewServer returns a new SASL server instance.
func NewServer() Server {
	server := &server{
		Provider: NewProvider(),
		Manager:  auth.NewManager(),
	}
	server.loadDefaultPlugins()
	return server
}

// Version returns the version.
func (server *server) Version() string {
	return Version
}

// Mechanisms returns the mechanisms.
func (server *server) Mechanisms() []Mechanism {
	ms := server.Provider.Mechanisms()
	opts := []mech.Option{
		server.CredentialStore(),
	}
	for _, m := range ms {
		m.SetOptions(opts...)
	}
	return ms
}

// Mechanism returns a mechanism by name.
func (server *server) Mechanism(name string) (Mechanism, error) {
	m, err := server.Provider.Mechanism(name)
	if err != nil {
		return nil, err
	}

	opts := []mech.Option{
		server.CredentialStore(),
	}
	m.SetOptions(opts...)

	return m, nil
}

func (server *server) loadDefaultPlugins() {
	server.AddMechanism(anonymous.NewServer())
	server.AddMechanism(plain.NewServer())
	for _, t := range scram.SCRAMTypes() {
		server.AddMechanism(scram.NewServerWithType(t))
	}
}
