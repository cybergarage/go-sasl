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

type Context struct {
	values map[string]any
}

// NewContext returns a new Context.
func NewContext() *Context {
	return &Context{
		values: make(map[string]any),
	}
}

// SetValue sets a value to the context.
func (ctx *Context) SetValue(key string, value any) {
	ctx.values[key] = value
}

// Value returns a value from the context.
func (ctx *Context) Value(key string) (any, bool) {
	value, hasValue := ctx.values[key]
	return value, hasValue
}