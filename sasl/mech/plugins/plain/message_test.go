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

package plain

import (
	"testing"
)

func TestPlainMessage(t *testing.T) {
	tests := []struct {
		message  []byte
		expected string
	}{
		{
			message:  []byte{0x00, 0x00, 0x63},
			expected: ",,c",
		},
		{
			message:  []byte{0x00, 0x62, 0x00, 0x63},
			expected: ",b,c",
		},
		{
			message:  []byte{0x00, 0x62, 0x00, 0x63},
			expected: ",b,c",
		},
		{
			message:  []byte{0x61, 0x00, 0x62, 0x00, 0x63},
			expected: "a,b,c",
		},
		{
			message:  []byte{0x61, 0x00, 0x62, 0x00, 0x63, 0x00},
			expected: "a,b,c",
		},
		{
			message:  []byte{0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64},
			expected: "a,b,c",
		},
		{
			message:  []byte{0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64, 0x00},
			expected: "a,b,c",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			msg, err := NewMessageFrom(test.message)
			if err != nil {
				t.Error(err)
				return
			}
			if msg.String() != test.expected {
				t.Errorf("got %s, want %s", msg.String(), test.expected)
			}
		})
	}
}
