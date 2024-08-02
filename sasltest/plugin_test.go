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

package sasltest

import (
	"testing"

	"github.com/cybergarage/go-sasl/sasl"
)

func TestMechanism(t *testing.T) {
	client := sasl.NewClient()
	server := sasl.NewServer()

	for _, clientMech := range client.Mechanisms() {
		t.Run(clientMech.Name(), func(t *testing.T) {
			serverMech, err := server.Mechanism(clientMech.Name())
			if err != nil {
				t.Error(err)
			}

			clientCtx, err := clientMech.Start()
			if err != nil {
				t.Error(err)
				return
			}

			serverCtx, err := serverMech.Start()
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

				if clientCtx.IsCompleted() {
					break
				}

				serverResponse, err := serverCtx.Next(clientResponse)
				if err != nil {
					t.Error(err)
					return
				}

				lastResponse = serverResponse
			}

			if !clientCtx.IsCompleted() {
				t.Error("client context is not completed")
			}

			if !serverCtx.IsCompleted() {
				t.Error("server context is not completed")
			}
		})
	}
}
