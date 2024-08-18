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

package anonymous

import (
	"fmt"

	"github.com/cybergarage/go-sasl/sasl/mech"
)

// Anonymous Simple Authentication and Security Layer (SASL) Mechanism
// https://www.rfc-editor.org/rfc/rfc4505.html

// Message represents a SASL ANONYMOUS message.
type Message string

// NewMessage returns a new ANONYMOUS message.
func NewMessageFrom(v any) (Message, error) {
	switch v := v.(type) {
	case Message:
		return v, nil
	case string:
		if 0 < len(v) {
			return Message(v), nil
		}
	case []byte:
		if 0 < len(v) {
			return Message(v), nil
		}
	case mech.Password:
		if 0 < len(v) {
			return Message(v), nil
		}
	}
	return "", fmt.Errorf("invalid type %T for ANONYMOUS message", v)
}
