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
	"testing"

	"github.com/cybergarage/go-sasl/sasl/scram"
	"github.com/cybergarage/go-sasl/sasltest"
)

func TestSCRAMExchange(t *testing.T) {
	user := sasltest.Username
	passwd := sasltest.Password

	hashFuncs := []scram.HashFunc{
		scram.HashSHA1(),
		scram.HashSHA256(),
		scram.HashSHA512(),
	}

	tests := []struct {
		clientFirstRS string
		serverFirstRS string
		salt          string
		ic            int
	}{
		// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
		// 5. SCRAM Authentication Exchange
		{
			clientFirstRS: "fyko+d2lbbFgONRv9qkxdawL",
			serverFirstRS: "3rfcNHYJY1ZVvWVs7j",
			salt:          "QSXCR+Q6sek8bf92",
			ic:            4096,
		},
		{
			clientFirstRS: "",
			serverFirstRS: "",
			salt:          "",
			ic:            0,
		},
	}

	for n, test := range tests {
		t.Run(fmt.Sprintf("test%02d", n), func(t *testing.T) {
			for _, hashFunc := range hashFuncs {
				t.Run(fmt.Sprintf("%d", hashFunc().Size()), func(t *testing.T) {
					var err error
					var client *scram.Client

					// Create a client
					client, err = scram.NewClient(
						scram.WithClientUsername(user),
						scram.WithClientPassword(passwd),
						scram.WithClientHashFunc(hashFunc))

					if err != nil {
						t.Error(err)
						return
					}

					clientOpts := []scram.ClientOption{}
					if 0 < len(test.clientFirstRS) {
						clientOpts = append(clientOpts, scram.WithClientRandomSequence(test.clientFirstRS))
					}
					client.SetOption(clientOpts...)

					// Create a server

					server, err := NewServer()
					if err != nil {
						t.Error(err)
						return
					}

					serverOpts := []scram.ServerOption{
						scram.WithServerHashFunc(hashFunc),
					}
					if 0 < len(test.serverFirstRS) {
						serverOpts = append(serverOpts, scram.WithServerRandomSequence(test.serverFirstRS))
					}
					if 0 < len(test.salt) {
						serverOpts = append(serverOpts, scram.WithServerSaltString(test.salt))
					}
					if 0 < test.ic {
						serverOpts = append(serverOpts, scram.WithServerIterationCount(test.ic))
					}
					server.SetOption(serverOpts...)

					// Exchange messages

					firstClientMsg, err := client.FirstMessage()
					if err != nil {
						t.Error(err)
						return
					}
					t.Logf("c1 = %s", firstClientMsg.String())

					firstServerMsg, err := server.FirstMessageFrom(firstClientMsg)
					if err != nil {
						t.Error(err)
						return
					}
					t.Logf("s1 = %s", firstServerMsg.String())

					finalClientMsg, err := client.FinalMessageFrom(firstServerMsg)
					if err != nil {
						t.Error(err)
						return
					}
					t.Logf("c2 = %s", finalClientMsg.String())

					finalServerMsg, err := server.FinalMessageFrom(finalClientMsg)
					if err != nil {
						t.Error(err)
						return
					}
					t.Logf("s2 = %s", finalServerMsg.String())

					err = client.ValidateServerFinalMessage(finalServerMsg)
					if err != nil {
						t.Error(err)
						return
					}
				})
			}
		})
	}
}
