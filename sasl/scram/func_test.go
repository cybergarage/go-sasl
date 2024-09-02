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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSaltedPassword(t *testing.T) {
	tests := []struct {
		hashfn         HashFunc
		password       string
		salt           string
		iterationCount int
		expected       string
	}{
		{
			sha256.New,
			"pencil", "ATHENA.MIT.EDUraeburn",
			4096,
			"93ce7dfda354911328861af885b907feb5aece70953c43cbe697ed2b1e368f95"},
	}

	for _, tt := range tests {
		actual, err := SaltedPassword(tt.hashfn, tt.password, []byte(tt.salt), tt.iterationCount)
		if err != nil {
			t.Error(err)
		}
		expected, err := hex.DecodeString(tt.expected)
		if err != nil {
			t.Error(err)
			continue
		}
		// saltedPassword := func(h HashFunc, passwd string, salt string, iters int) []byte {
		// 	return pbkdf2.Key([]byte(passwd), []byte(salt), iters, h().Size(), h)
		// }
		// saltedPassword(tt.hashfn, tt.password, tt.salt, tt.iterationCount)
		if !bytes.Equal(actual, expected) {
			t.Errorf("actual=%s, expected=%s", hex.EncodeToString(actual), tt.expected)
		}
	}
}
