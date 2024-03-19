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

// Plain represents a PLAIN mechanism.
type Plain struct {
}

// NewPlain returns a new PLAIN mechanism.
func NewPlain() *Plain {
	return &Plain{}
}

// Name returns the mechanism name.
func (m *Plain) Name() string {
	return "PLAIN"
}

// Start returns the initial response.
func (m *Plain) Start() ([]byte, error) {
	return nil, nil
}

// Next returns the next response.
func (m *Plain) Next(challenge []byte) ([]byte, error) {
	return nil, nil
}
