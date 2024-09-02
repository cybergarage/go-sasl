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

package mech

import (
	"github.com/cybergarage/go-safecast/safecast"
)

type store struct {
	values map[string]any
}

// NewContext returns a new Context.
func NewStore() Store {
	return &store{
		values: make(map[string]any),
	}
}

// SetValue sets a value to the context.
func (ctx *store) SetValue(key string, value any) {
	ctx.values[key] = value
}

// Value returns a value from the context.
func (ctx *store) Value(key string) (any, bool) {
	value, hasValue := ctx.values[key]
	return value, hasValue
}

// StringValue returns the context value as a string.
func (ctx *store) StringValue(key string) (string, bool) {
	value, hasValue := ctx.values[key]
	if !hasValue {
		return "", false
	}
	var strValue string
	err := safecast.ToString(value, &strValue)
	if err != nil {
		return "", false
	}
	return strValue, true
}

// BytesValue returns the context value as a byte slice.
func (ctx *store) BytesValue(key string) ([]byte, bool) {
	value, hasValue := ctx.values[key]
	if !hasValue {
		return nil, false
	}
	var byteValue []byte
	err := safecast.ToBytes(value, &byteValue)
	if err != nil {
		return nil, false
	}
	return byteValue, true
}

// IntValue returns the context value as an integer.
func (ctx *store) IntValue(key string) (int, bool) {
	value, hasValue := ctx.values[key]
	if !hasValue {
		return 0, false
	}
	var intValue int
	err := safecast.ToInt(value, &intValue)
	if err != nil {
		return 0, false
	}
	return intValue, true
}

// BoolValue returns the context value as a boolean.
func (ctx *store) BoolValue(key string) (bool, bool) {
	value, hasValue := ctx.values[key]
	if !hasValue {
		return false, false
	}
	var boolValue bool
	err := safecast.ToBool(value, &boolValue)
	if err != nil {
		return false, false
	}
	return boolValue, true
}
