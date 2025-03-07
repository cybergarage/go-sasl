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

// Type represents a SCRAM type.
type Type int

const (
	SHA1 Type = iota
	SHA256
	SHA512
)

// SCRAMTypes returns the SCRAM types.
func SCRAMTypes() []Type {
	return []Type{
		SHA1,
		SHA256,
		SHA512,
	}
}

// SCRAMType returns the SCRAM type.
func (t Type) String() string {
	switch t {
	case SHA1:
		return "SHA-1"
	case SHA256:
		return "SHA-256"
	case SHA512:
		return "SHA-512"
	}
	return ""
}
