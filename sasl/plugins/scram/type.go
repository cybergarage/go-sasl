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

// SCRAMType represents a SCRAM type.
type SCRAMType int

const (
	SCRAMTypeSHA1 SCRAMType = iota
	SCRAMTypeSHA256
	SCRAMTypeSHA512
)

// SCRAMTypes returns the SCRAM types.
func SCRAMTypes() []SCRAMType {
	return []SCRAMType{
		SCRAMTypeSHA1,
		SCRAMTypeSHA256,
		SCRAMTypeSHA512,
	}
}

// SCRAMType returns the SCRAM type.
func (t SCRAMType) String() string {
	switch t {
	case SCRAMTypeSHA1:
		return "SHA-1"
	case SCRAMTypeSHA256:
		return "SHA-256"
	case SCRAMTypeSHA512:
		return "SHA-512"
	}
	return ""
}
