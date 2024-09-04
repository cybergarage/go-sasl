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

package xdg

import (
	"testing"

	"github.com/cybergarage/go-sasl/sasl/scram"
	scramtest "github.com/cybergarage/go-sasl/sasltest/scram"
	xgoscram "github.com/xdg-go/scram"
)

func ClientTestWithXdg(t *testing.T) {
	kf := xgoscram.KeyFactors{
		Salt:  "salt",
		Iters: 4096,
	}

	calculateServerKeys := func(hf scram.HashFunc, password []byte, salt []byte, ic int) ([]byte, []byte, error) {
		saltedPassword, err := scram.SaltedPassword(hf, string(password), salt, ic)
		if err != nil {
			return nil, nil, err
		}
		clientKey := scram.ClientKey(hf, saltedPassword)
		storedKey := scram.StoredKey(hf, clientKey)
		serverKey := scram.ServerKey(hf, saltedPassword)
		return storedKey, serverKey, nil
	}

	// SCRAM-SHA1 Server

	credLookupSHA1 := func(string) (xgoscram.StoredCredentials, error) {
		storedKey, serverKey, err := calculateServerKeys(scram.HashSHA1(), []byte(scramtest.Password), []byte(kf.Salt), kf.Iters)
		if err != nil {
			return xgoscram.StoredCredentials{}, err
		}
		return xgoscram.StoredCredentials{
			KeyFactors: kf,
			StoredKey:  storedKey,
			ServerKey:  serverKey,
		}, nil
	}
	sha1Server, err := xgoscram.SHA1.NewServer(credLookupSHA1)
	if err != nil {
		t.Error(err)
		return
	}

	// SCRAM-SHA256 Server

	credLookupSHA256 := func(string) (xgoscram.StoredCredentials, error) {
		storedKey, serverKey, err := calculateServerKeys(scram.HashSHA256(), []byte(scramtest.Password), []byte(kf.Salt), kf.Iters)
		if err != nil {
			return xgoscram.StoredCredentials{}, err
		}
		return xgoscram.StoredCredentials{
			KeyFactors: kf,
			StoredKey:  storedKey,
			ServerKey:  serverKey,
		}, nil
	}
	sha256Server, err := xgoscram.SHA256.NewServer(credLookupSHA256)
	if err != nil {
		t.Error(err)
		return
	}

	tests := []struct {
		name string
		scram.HashFunc
		server *xgoscram.Server
	}{
		{
			name:     "SCRAM-SHA1",
			HashFunc: scram.HashSHA1(),
			server:   sha1Server,
		},
		{
			name:     "SCRAM-SHA256",
			HashFunc: scram.HashSHA256(),
			server:   sha256Server,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := scram.NewClient()
			if err != nil {
				t.Error(err)
				return
			}
			clientOpts := []scram.ClientOption{
				scram.WithClientUsername(scramtest.Username),
				scram.WithClientPassword(scramtest.Password),
				scram.WithClientHashFunc(test.HashFunc),
			}
			client.SetOptions(clientOpts...)

			// Client first message

			clientMsg, err := client.FirstMessage()
			if err != nil {
				t.Error(err)
				return
			}

			t.Logf("[c1] %s", clientMsg.String())

			// Server first message

			conv := test.server.NewConversation()
			serverMsg, err := conv.Step(clientMsg.String())
			if err != nil {
				t.Error(err)
				return
			}

			t.Logf("[s1] %s", serverMsg)

			// Client final message

			msg, err := scram.NewMessageFrom(serverMsg)
			if err != nil {
				t.Error(err)
				return
			}

			clientMsg, err = client.FinalMessageFrom(msg)
			if err != nil {
				t.Error(err)
				return
			}

			t.Logf("[c1] %s", clientMsg.String())

			// Server final message

			serverMsg, err = conv.Step(clientMsg.String())
			if err != nil {
				t.Error(err)
				return
			}

			t.Logf("[s2] %s", serverMsg)

			// Client validation

			msg, err = scram.NewMessageFrom(serverMsg)
			if err != nil {
				t.Error(err)
				return
			}

			err = client.ValidateServerFinalMessage(msg)
			if err != nil {
				t.Error(err)
				return
			}
		})
	}
}
