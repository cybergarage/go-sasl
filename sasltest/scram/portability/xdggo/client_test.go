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

package xdggo

import (
	"testing"

	"github.com/cybergarage/go-sasl/sasl/scram"
	scramtest "github.com/cybergarage/go-sasl/sasltest/scram"
	xgoscram "github.com/xdg-go/scram"
)

func TestClientWithXdg(t *testing.T) {

	credLookup := func(string) (xgoscram.StoredCredentials, error) {
		return xgoscram.StoredCredentials{
			KeyFactors: xgoscram.KeyFactors{
				Salt:  "salt",
				Iters: 4096,
			},
			StoredKey: []byte("storedkey"),
			ServerKey: []byte("serverkey"),
		}, nil
	}

	_, err := xgoscram.SHA1.NewServer(credLookup)
	if err != nil {
		t.Error(err)
		return
	}

	sha1Client, err := xgoscram.SHA1.NewClientUnprepped(scramtest.Username, scramtest.Password, "")
	if err != nil {
		t.Error(err)
		return
	}

	sha256Client, err := xgoscram.SHA256.NewClientUnprepped(scramtest.Username, scramtest.Password, "")
	if err != nil {
		t.Error(err)
		return
	}

	tests := []struct {
		name   string
		client *xgoscram.Client
		scram.HashFunc
	}{
		{
			name:     "xdg-go-scram-SHA1",
			client:   sha1Client,
			HashFunc: scram.HashSHA1(),
		},
		{
			name:     "xdg-go-scram-SHA256",
			client:   sha256Client,
			HashFunc: scram.HashSHA256(),
		},
	}

	t.Run("xdg-go/", func(t *testing.T) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				server, err := scramtest.NewServer()
				if err != nil {
					t.Error(err)
					return
				}
				serverOpts := []scram.ServerOption{
					scram.WithServerHashFunc(test.HashFunc),
				}
				server.SetOption(serverOpts...)

				// Client first message

				conv := test.client.NewConversation()
				clientMsg, err := conv.Step("")
				if err != nil {
					t.Error(err)
					return
				}

				// Server first message

				msg, err := scram.NewMessageFromWithHeader(clientMsg)
				if err != nil {
					t.Error(err)
					return
				}

				serverMsg, err := server.FirstMessageFrom(msg)
				if err != nil {
					t.Error(err)
					return
				}

				// Client final message

				clientMsg, err = conv.Step(serverMsg.String())
				if err != nil {
					t.Error(err)
					return
				}

				// Server final message

				msg, err = scram.NewMessageFrom(clientMsg)
				if err != nil {
					t.Error(err)
					return
				}

				serverMsg, err = server.FinalMessageFrom(msg)
				if err != nil {
					t.Error(err)
					return
				}

				// Client validation

				_, err = conv.Step(serverMsg.String())
				if err != nil {
					t.Error(err)
					return
				}
			})
		}
	})
}
