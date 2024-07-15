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
	"testing"

	"github.com/cybergarage/go-sasl/sasl/scram"
	"github.com/cybergarage/go-sasl/sasltest"
)

func TestSCRAMExchange(t *testing.T) {
	hashFunc := scram.HashSHA256()
	authzID := sasltest.AuthzID
	user := sasltest.Username
	passwd := sasltest.Paassword

	tests := []struct {
		firstClientMsgStr string
	}{
		// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
		// 5. SCRAM Authentication Exchange
		{
			firstClientMsgStr: "",
		},
		{
			firstClientMsgStr: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
		},
	}

	for _, test := range tests {
		var err error
		var client *scram.Client

		if 0 < len(test.firstClientMsgStr) {
			client, err = scram.NewClientFromMessageWithHeader(test.firstClientMsgStr)
			if err != nil {
				t.Error(err)
				continue
			}
		} else {
			client, err = scram.NewClient(
				scram.WithAuthzID(authzID), scram.WithUsername(user), scram.WithPassword(passwd), scram.WithHashFunc(hashFunc))
			if err != nil {
				t.Error(err)
				continue
			}
		}
		firstClientMsg, err := client.FirstMessage()
		if err != nil {
			t.Error(err)
			continue
		}
		server, err := sasltest.NewServer()
		if err != nil {
			t.Error(err)
			continue
		}
		firstServerMsg, err := server.FirstMessageFrom(firstClientMsg)
		if err != nil {
			t.Error(err)
			continue
		}

		finalClientMsg, err := client.FinalMessageFrom(firstServerMsg)
		if err != nil {
			t.Error(err)
			continue
		}

		_, err = server.FinalMessageFrom(finalClientMsg)
		if err != nil {
			t.Error(err)
			continue
		}
	}
}