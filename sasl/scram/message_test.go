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
)

func TestSCRAMMessage(t *testing.T) {
	type expected struct {
		userName           string
		randomSequence     string
		salt               string
		iterationCount     string
		channelBindingData string
		clientProof        string
	}

	tests := []struct {
		messageStr string
		hasHeader  bool
		expected   expected
	}{
		// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
		// 5. SCRAM Authentication Exchange
		{
			messageStr: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
			hasHeader:  true,
			expected: expected{
				userName:           "user",
				randomSequence:     "fyko+d2lbbFgONRv9qkxdawL",
				salt:               "",
				iterationCount:     "",
				channelBindingData: "",
				clientProof:        "",
			},
		},
		{
			messageStr: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
			hasHeader:  false,
			expected: expected{
				userName:           "",
				randomSequence:     "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j",
				salt:               "QSXCR+Q6sek8bf92",
				iterationCount:     "4096",
				channelBindingData: "",
				clientProof:        "",
			},
		},
		{
			messageStr: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
			hasHeader:  false,
			expected: expected{
				userName:           "",
				randomSequence:     "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j",
				salt:               "",
				iterationCount:     "",
				channelBindingData: "biws",
				clientProof:        "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
			},
		},
	}

	for _, test := range tests {
		msg := NewMessage()
		if test.hasHeader {
			if err := msg.ParseStringWithHeader(test.messageStr); err != nil {
				t.Error(err)
				continue
			}
		} else {
			if err := msg.ParseString(test.messageStr); err != nil {
				t.Error(err)
				continue
			}
		}

		if 0 < len(test.expected.userName) {
			v, ok := msg.UserName()
			if !ok || v != test.expected.userName {
				t.Errorf("userName = %s, want %s", v, test.expected.userName)
			}
		}

		if 0 < len(test.expected.randomSequence) {
			v, ok := msg.RandomSequence()
			if !ok || v != test.expected.randomSequence {
				t.Errorf("randomSequence = %s, want %s", v, test.expected.randomSequence)
			}
		}

		if 0 < len(test.expected.salt) {
			v, ok := msg.Salt()
			if !ok || v != test.expected.salt {
				t.Errorf("salt = %s, want %s", v, test.expected.salt)
			}
		}

		if 0 < len(test.expected.iterationCount) {
			v, ok := msg.IterationCount()
			if !ok || v != test.expected.iterationCount {
				t.Errorf("iterationCount = %s, want %s", v, test.expected.iterationCount)
			}
		}

		if 0 < len(test.expected.channelBindingData) {
			v, ok := msg.ChannelBindingData()
			if !ok || v != test.expected.channelBindingData {
				t.Errorf("channelBindingData = %s, want %s", v, test.expected.channelBindingData)
			}
		}

		if 0 < len(test.expected.clientProof) {
			v, ok := msg.ClientProof()
			if !ok || v != test.expected.clientProof {
				t.Errorf("clientProof = %s, want %s", v, test.expected.clientProof)
			}
		}
	}
}
