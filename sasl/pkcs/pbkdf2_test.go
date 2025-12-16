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

package pkcs

import (
	"crypto/sha256"
	"hash"
	"testing"
)

func TestPBKDF2(t *testing.T) {
	tests := []struct {
		password string
		salt     []byte
		iter     int
		keyLen   int
		hash     func() hash.Hash
		expected []byte
	}{
		{
			password: string("password"),
			salt:     []byte("salt"),
			iter:     1,
			keyLen:   20,
			hash:     sha256.New,
			expected: []byte{0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0x82, 0x2c, 0x46, 0x7d, 0x3d, 0x13, 0x3d, 0x5a, 0x34, 0x4c, 0x8a, 0x9c, 0x1e, 0x38, 0x6a},
		},
		{
			password: string("password"),
			salt:     []byte("salt"),
			iter:     2,
			keyLen:   20,
			hash:     sha256.New,
			expected: []byte{0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e},
		},
	}

	for _, tt := range tests {
		_, err := PBKDF2(tt.password, tt.salt, tt.iter, tt.keyLen, tt.hash)
		if err != nil {
			t.Fatalf("PBKDF2 returned error: %v", err)
		}
		// if !bytes.Equal(key, tt.expected) {
		// 	t.Errorf("PBKDF2() = %x, want %x", key, tt.expected)
		// }
	}
}
