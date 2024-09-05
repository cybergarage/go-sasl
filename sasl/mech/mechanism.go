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

// Parameter represents a SASL mechanism parameter.
type Parameter = any

// Response represents a SASL mechanism response.
type Response interface {
	// Bytes returns the response bytes.
	Bytes() []byte
	// String returns the response as a string.
	String() string
}

// Store represents a SASL mechanism store.
type Store interface {
	// SetValue sets the context value.
	SetValue(key string, value any)
	// Value returns the context value.
	Value(key string) (any, bool)
	// ValueTo returns the context value as a specific type.
	ValueTo(key string, v any) bool
	// StringValue returns the context value as a string.
	StringValue(key string) (string, bool)
	// BytesValue returns the context value as a byte slice.
	BytesValue(key string) ([]byte, bool)
	// IntValue returns the context value as an integer.
	IntValue(key string) (int, bool)
	// BoolValue returns the context value as a boolean.
	BoolValue(key string) (bool, bool)
}

// Context represents a SASL mechanism context.
type Context interface {
	// Store represents a SASL mechanism store.
	Store
	// Next returns the next response.
	Next(...Parameter) (Response, error)
	// Step returns the current step number. The step number is incremented by one after each call to Next.
	Step() int
	// Done returns true if the context is completed.
	Done() bool
	// Dispose disposes the context.
	Dispose() error
}

// Mechanism represents a SASL mechanism.
type Mechanism interface {
	// Name returns the mechanism name.
	Name() string
	// Type returns the mechanism type.
	Type() Type
	// Start returns the initial context.
	Start(...Option) (Context, error)
}
