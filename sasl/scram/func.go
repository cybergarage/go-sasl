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
// 2.2. Notation.
// Hi(str, salt, i) is defined as:.
func Hi(str string, salt string, i int) string {
	var u string
	u = HMAC(str, salt+strconv.Itoa(1))
	for n := 1; n < i; n++ {
		u = HMAC(str, u)
	}
	return u
}

// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
// https://datatracker.ietf.org/doc/html/rfc5802
// 2.2. Notation
// RFC - HMAC: Keyed-Hashing for Message Authentication
// https://datatracker.ietf.org/doc/html/rfc2104
// HMAC(key, data) is defined as:.
func HMAC(key, data string) string {
	return ""
}
