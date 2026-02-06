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

// Package scram provides hash functions for SCRAM authentication mechanisms.
//
// nolint: gosec
package scram

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

const (
	// SHA1 is the SHA-1 hash function.
	SHA1 = "SCRAM-SHA-1"
	// SHA256 is the SHA-256 hash function.
	SHA256 = "SCRAM-SHA-256"
	// SHA512 is the SHA-512 hash function.
	SHA512 = "SCRAM-SHA-512"
)

// HashFunc is a function that returns a hash.Hash.
type HashFunc = func() hash.Hash

// HashSHA512 returns a new SHA-512 hash function.
func HashSHA512() HashFunc {
	return sha512.New
}

// HashSHA256 returns a new SHA-256 hash function.
func HashSHA256() HashFunc {
	return sha256.New
}

// HashSHA1 returns a new SHA-1 hash function.
func HashSHA1() HashFunc {
	return sha1.New
}
