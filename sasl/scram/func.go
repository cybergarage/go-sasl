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
	"strconv"
)

// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
// https://datatracker.ietf.org/doc/html/rfc5802

// Hi(str, salt, i) is defined as:.
// 2.2. Notation.
func Hi(str string, salt string, i int) string {
	if i <= 1 {
		return ""
	}
	u := make([]string, i)
	u[0] = HMAC(str, salt+strconv.Itoa(1))
	for n := 1; n < i; n++ {
		u[n] = HMAC(str, u[n-1])
	}
	var hi string
	hi = u[0]
	for n := 1; n < i; n++ {
		hi = XOR(hi, u[n])
	}
	return hi
}

// HMAC(key, data) is defined as:.
// 2.2. Notation
// RFC - HMAC: Keyed-Hashing for Message Authentication
// https://datatracker.ietf.org/doc/html/rfc2104
func HMAC(key, data string) string {
	return ""
}

// H(data) is defined as:.
// 2.2. Notation.
func H(data string) string {
	return data
}

// XOR(a, b) is defined as:.
// 2.2. Notation.
func XOR(a, b string) string {
	return ""
}

// Normalize(str) is defined as:.
// 2.2. Notation.
func Normalize(str string) string {
	return str
}

// SaltedPassword  := Hi(Normalize(password), salt, i).
func SaltedPassword(password, salt string, i int) string {
	return Hi(Normalize(password), salt, i)
}

// ClientKey       := HMAC(SaltedPassword, "Client Key").
func ClientKey(saltedPassword string) string {
	return HMAC(saltedPassword, "Client Key")
}

// StoredKey       := H(ClientKey).
func StoredKey(clientKey string) string {
	return H(clientKey)
}

// AuthMessage     := client-first-message-bare + "," +
// 				   server-first-message + "," +
// 				   client-final-message-without-proof

// ClientSignature := HMAC(StoredKey, AuthMessage).
func ClientSignature(storedKey, authMessage string) string {
	return HMAC(storedKey, authMessage)
}

// ClientProof     := ClientKey XOR ClientSignature
// func ClientProof(clientKey, clientSignature string) string {
// 	return XOR(clientKey, clientSignature)
// }

// ServerKey       := HMAC(SaltedPassword, "Server Key").
func ServerKey(saltedPassword string) string {
	return HMAC(saltedPassword, "Server Key")
}

// ServerSignature := HMAC(ServerKey, AuthMessage)
// func ServerSignature(serverKey, authMessage string) string {
// 	return HMAC(serverKey, authMessage)
// }
