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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cybergarage/go-sasl/sasl/scram"
	"github.com/xdg-go/pbkdf2"
)

func SaltedPasswordTest(t *testing.T) {
	t.Helper()

	saltedPassword := func(h scram.HashFunc, passwd string, salt string, iters int) []byte {
		return pbkdf2.Key([]byte(passwd), []byte(salt), iters, h().Size(), h)
	}

	tests := []struct {
		hashfn         scram.HashFunc
		password       string
		salt           string
		iterationCount int
	}{
		{
			sha256.New,
			"pencil",
			"ATHENA.MIT.EDUraeburn",
			4096,
		},
	}

	for _, tt := range tests {
		actual, err := scram.SaltedPassword(tt.hashfn, tt.password, []byte(tt.salt), tt.iterationCount)
		if err != nil {
			t.Error(err)
		}
		expected := saltedPassword(tt.hashfn, tt.password, tt.salt, tt.iterationCount)
		if !bytes.Equal(actual, expected) {
			t.Errorf("actual=%s, expected=%s", hex.EncodeToString(actual), expected)
		}
	}
}
