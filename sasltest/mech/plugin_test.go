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

package mech

import (
	"testing"

	"github.com/cybergarage/go-sasl/sasl"
	"github.com/cybergarage/go-sasl/sasl/mech"
	"github.com/cybergarage/go-sasl/sasltest"
)

func TestMechanism(t *testing.T) {
	client := sasl.NewClient()
	server := sasltest.NewServer()

	clientOpts := []mech.Option{
		mech.Username(sasltest.Username),
		mech.Password(sasltest.Password),
		mech.Token(sasltest.Username),
	}

	serverOpts := []mech.Option{
		server.CredentialStore(),
	}

	for _, clientMech := range client.Mechanisms() {
		t.Run(clientMech.Name(), func(t *testing.T) {
			serverMech, err := server.Mechanism(clientMech.Name())
			if err != nil {
				t.Error(err)
				return
			}

			clientCtx, err := clientMech.Start(clientOpts...)
			if err != nil {
				t.Error(err)
				return
			}

			serverCtx, err := serverMech.Start(serverOpts...)
			if err != nil {
				t.Error(err)
				return
			}

			var lastResponse sasl.Response
			for {
				clientResponse, err := clientCtx.Next(lastResponse)
				if err != nil {
					t.Error(err)
					return
				}

				if clientResponse != nil {
					t.Logf("c%d: %v", clientCtx.Step(), clientResponse)
				} else {
					t.Logf("c%d:", clientCtx.Step())
				}

				if serverCtx.Done() {
					break
				}

				serverResponse, err := serverCtx.Next(clientResponse)
				if err != nil {
					t.Error(err)
					return
				}

				if serverResponse != nil {
					t.Logf("s%d: %v", serverCtx.Step(), serverResponse)
				} else {
					t.Logf("s%d:", serverCtx.Step())
				}

				if clientCtx.Done() {
					break
				}

				lastResponse = serverResponse
			}

			if !clientCtx.Done() {
				t.Error("client context is not completed")
			}

			if !serverCtx.Done() {
				t.Error("server context is not completed")
			}

			err = clientCtx.Dispose()
			if err != nil {
				t.Error(err)
			}

			err = serverCtx.Dispose()
			if err != nil {
				t.Error(err)
			}
		})
	}
}
