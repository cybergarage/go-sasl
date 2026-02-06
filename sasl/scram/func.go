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
	"crypto/hmac"

	"github.com/cybergarage/go-sasl/sasl/prep"
)

// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
// https://datatracker.ietf.org/doc/html/rfc5802

// Hi(str, salt, i) is defined as:.
// 2.2. Notation.
func Hi(h HashFunc, str string, salt []byte, i int) []byte {
	if i <= 1 {
		return []byte{}
	}
	// salt + INT(1)
	// INT(g) is a 4-octet encoding of the integer g, most significant octet first.
	saltInt1 := make([]byte, len(salt), len(salt)+4)
	copy(saltInt1, salt)
	saltInt1 = append(saltInt1, 0x00, 0x00, 0x00, 0x01)
	// U1   := HMAC(str, salt + INT(1))
	// U2   := HMAC(str, U1)
	// ...
	// Ui-1 := HMAC(str, Ui-2)
	// Ui   := HMAC(str, Ui-1)
	u := make([][]byte, i)
	u[0] = HMAC(h, []byte(str), saltInt1)
	for n := 1; n < i; n++ {
		u[n] = HMAC(h, []byte(str), u[n-1])
	}
	// Hi := U1 XOR U2 XOR ... XOR Ui
	hi := make([]byte, len(u[0]))
	copy(hi, u[0])
	for n := 1; n < i; n++ {
		hi = XOR(hi, u[n])
	}
	return hi[0:h().Size()]
}

// HMAC(key, data) is defined as:.
// 2.2. Notation
// RFC 2104　- HMAC: Keyed-Hashing for Message Authentication
// https://datatracker.ietf.org/doc/html/rfc2104
func HMAC(hf HashFunc, key []byte, data []byte) []byte {
	mac := hmac.New(hf, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// H(data) is defined as:.
// 2.2. Notation.
func H(hf HashFunc, data []byte) []byte {
	h := hf()
	h.Write(data)
	return h.Sum(nil)
}

// XOR(a, b) is defined as:.
// 2.2. Notation.
func XOR(a, b []byte) []byte {
	minLength := min(len(a), len(b))
	result := make([]byte, minLength)
	for n := range minLength {
		result[n] = a[n] ^ b[n]
	}
	return result
}

// SaltedPassword  := Hi(Normalize(password), salt, i).
func SaltedPassword(h HashFunc, password string, salt []byte, i int) ([]byte, error) {
	prepPassword, err := prep.Normalize(password)
	if err != nil {
		return nil, err
	}
	return Hi(h, prepPassword, salt, i), nil
}

// ClientKey       := HMAC(SaltedPassword, "Client Key").
func ClientKey(h HashFunc, saltedPassword []byte) []byte {
	return HMAC(h, saltedPassword, []byte("Client Key"))
}

// StoredKey       := H(ClientKey).
func StoredKey(h HashFunc, clientKey []byte) []byte {
	return H(h, clientKey)
}

// AuthMessage     := client-first-message-bare + "," +
//
//	server-first-message + "," +
//	client-final-message-without-proof
func AuthMessage(clientFirstMessageBare, serverFirstMessage, clientFinalMessageWithoutProof string) string {
	return clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof
}

// ClientSignature := HMAC(StoredKey, AuthMessage).
func ClientSignature(h HashFunc, storedKey, authMessage string) []byte {
	return HMAC(h, []byte(storedKey), []byte(authMessage))
}

// ClientProof     := ClientKey XOR ClientSignature.
func ClientProof(clientKey, clientSignature string) []byte {
	return XOR([]byte(clientKey), []byte(clientSignature))
}

// ServerKey       := HMAC(SaltedPassword, "Server Key").
func ServerKey(h HashFunc, saltedPassword []byte) []byte {
	return HMAC(h, saltedPassword, []byte("Server Key"))
}

// ServerSignature := HMAC(ServerKey, AuthMessage).
func ServerSignature(h HashFunc, serverKey, authMessage string) []byte {
	return HMAC(h, []byte(serverKey), []byte(authMessage))
}
