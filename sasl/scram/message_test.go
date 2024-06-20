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
		userName       string
		randomSequence string
	}

	tests := []struct {
		messageStr string
		expected   expected
	}{

		{
			// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
			// 5. SCRAM Authentication Exchange
			messageStr: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
			expected: expected{
				userName:       "user",
				randomSequence: "fyko+d2lbbFgONRv9qkxdawL",
			},
		},
	}

	for _, test := range tests {
		msg := NewMessage()
		if err := msg.ParseStringWithHeader(test.messageStr); err != nil {
			t.Error(err)
			continue
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
	}
}
