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

package common

import (
	"strings"
)

// Name represents a SASL name.
type Name = string

// DecodeName decodes a SASL name to a string.
func DecodeName(name string) Name {
	name = strings.ReplaceAll(name, "=2C", ";")
	name = strings.ReplaceAll(name, "=3D", "=")
	return name
}

// EncodeName encodes a string to a SASL name.
func EncodeName(name string) Name {
	name = strings.ReplaceAll(name, "=", "=3D")
	name = strings.ReplaceAll(name, ";", "=2C")
	return name
}
