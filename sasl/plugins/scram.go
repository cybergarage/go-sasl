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

package plugins

// SCRAM represents a PLAIN mechanism.
type SCRAM struct {
	typ SCRAMType
}

// NewSCRAM returns a new PLAIN mechanism.
func NewSCRAMWithType(t SCRAMType) Mechanism {
	return &SCRAM{
		typ: t,
	}
}

// Name returns the mechanism name.
func (m *SCRAM) Name() string {
	return "SCRAM-" + m.typ.String()
}

// Type returns the SCRAM type.
func (m *SCRAM) Type() SCRAMType {
	return m.typ
}

// Start returns the initial response.
func (m *SCRAM) Start() ([]byte, error) {
	return nil, nil
}

// Next returns the next response.
func (m *SCRAM) Next(challenge []byte) ([]byte, error) {
	return nil, nil
}
