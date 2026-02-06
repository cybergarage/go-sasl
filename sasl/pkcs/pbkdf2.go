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
	"crypto/pbkdf2"
	"hash"
)

// RFC 2898 - PKCS #5: Password-Based Cryptography Specification Version 2.0
// https://datatracker.ietf.org/doc/html/rfc2898
// 5.2 PBKDF2.
// PBKDF2 applies a pseudorandom function to derive keys.

// PBKDF2 derives a key from the password, salt, iteration count, key length, and hash function.
func PBKDF2(password string, salt []byte, iter int, keyLength int, hash func() hash.Hash) ([]byte, error) {
	// 5.2 PBKDF2
	// https://datatracker.ietf.org/doc/html/rfc2898#section-5.2
	// PBKDF2 (P, S, c, dkLen)
	// 1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and stop.
	// 2. l = CEIL (dkLen / hLen).
	// 3. r = dkLen - (l - 1) * hLen.
	// 4. For i = 1, 2, ..., l, do
	//    a. Ti = F (P, S || INT (i)).
	//    b. U1 = T1; U2 = F (P, U1); ...; Ul = F (P, Ul-1).
	// 5. Output the first dkLen octets of T1 || T2 || ... || Tr.
	return pbkdf2.Key(hash, password, salt, iter, keyLength)
}
