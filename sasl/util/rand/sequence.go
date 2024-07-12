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

package rand

import (
	"crypto/rand"
)

// RandomSequence represents a random sequence.
type RandomSequence string

// NewRandomSequence creates a new random sequence.
func NewRandomSequence(length int) (RandomSequence, error) {
	// RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms
	// https://datatracker.ietf.org/doc/html/rfc5802
	// 5.1. SCRAM Attributes
	// RFC 4086 - Randomness Requirements for Security
	// https://datatracker.ietf.org/doc/html/rfc4086

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[]|:;<>.?~"
	randomBytes := make([]byte, length)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	result := make([]byte, length)
	for i, b := range randomBytes {
		result[i] = charset[b%byte(len(charset))]
	}

	return RandomSequence(result), nil
}

// String returns the string of the random sequence.
func (seq RandomSequence) String() string {
	return string(seq)
}
