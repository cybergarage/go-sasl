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
	"encoding/hex"
	"strconv"

	"github.com/cybergarage/go-sasl/sasl/prep"
)

// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
// https://datatracker.ietf.org/doc/html/rfc5802

// Hi(str, salt, i) is defined as:.
// 2.2. Notation.
func Hi(h HashFunc, str string, salt string, i int) string {
	if i <= 1 {
		return ""
	}
	u := make([]string, i)
	u[0] = HMAC(h, str, salt+strconv.Itoa(1))
	for n := 1; n < i; n++ {
		u[n] = HMAC(h, str, u[n-1])
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
// RFC 2104　- HMAC: Keyed-Hashing for Message Authentication
// https://datatracker.ietf.org/doc/html/rfc2104
func HMAC(h HashFunc, key string, data string) string {
	mac := hmac.New(h, []byte(key))
	mac.Write([]byte(data))
	signedByte := mac.Sum(nil)
	return hex.EncodeToString(signedByte)
}

// H(data) is defined as:.
// 2.2. Notation.
func H(hf HashFunc, data string) string {
	h := hf()
	h.Write([]byte(data))
	return string(h.Sum(nil))
}

// XOR(a, b) is defined as:.
// 2.2. Notation.
func XOR(a, b string) string {
	minLength := len(a)
	if len(b) < minLength {
		minLength = len(b)
	}
	result := make([]byte, minLength)
	for i := 0; i < minLength; i++ {
		result[i] = a[i] ^ b[i]
	}
	return string(result)
}

// SaltedPassword  := Hi(Normalize(password), salt, i).
func SaltedPassword(h HashFunc, password string, salt string, i int) (string, error) {
	prepPassword, err := prep.Normalize(password)
	if err != nil {
		return "", err
	}
	return Hi(h, prepPassword, salt, i), nil
}

// ClientKey       := HMAC(SaltedPassword, "Client Key").
func ClientKey(h HashFunc, saltedPassword string) string {
	return HMAC(h, saltedPassword, "Client Key")
}

// StoredKey       := H(ClientKey).
func StoredKey(h HashFunc, clientKey string) string {
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
func ClientSignature(h HashFunc, storedKey, authMessage string) string {
	return HMAC(h, storedKey, authMessage)
}

// ClientProof     := ClientKey XOR ClientSignature.
func ClientProof(clientKey, clientSignature string) string {
	return XOR(clientKey, clientSignature)
}

// ServerKey       := HMAC(SaltedPassword, "Server Key").
func ServerKey(h HashFunc, saltedPassword string) string {
	return HMAC(h, saltedPassword, "Server Key")
}

// ServerSignature := HMAC(ServerKey, AuthMessage).
func ServerSignature(h HashFunc, serverKey, authMessage string) string {
	return HMAC(h, serverKey, authMessage)
}
