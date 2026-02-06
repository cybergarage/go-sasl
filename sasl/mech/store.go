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
	"errors"

	"github.com/cybergarage/go-safecast/safecast"
)

// ErrNotFound represents a not found error.
var ErrNotFound = errors.New("not found")

type store struct {
	values map[string]any
}

// NewStore returns a new mechanism store.
func NewStore() Store {
	return &store{
		values: make(map[string]any),
	}
}

// SetValue sets a value to the store.
func (ctx *store) SetValue(key string, value any) {
	ctx.values[key] = value
}

// Value returns a value from the store.
func (ctx *store) Value(key string) (any, bool) {
	value, hasValue := ctx.values[key]
	return value, hasValue
}

// ValueTo returns the context value as a specific type.
func (ctx *store) ValueTo(key string, v any) bool {
	value, hasValue := ctx.values[key]
	if !hasValue {
		return false
	}
	return safecast.To(value, v) == nil
}
