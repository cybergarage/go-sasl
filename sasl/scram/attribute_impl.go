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

// attribute represents a SCRAM attribute.
type attribute struct {
	name  string
	value string
}

// NewAttribute returns a new SASL attribute.
func NewAttribute(name, value string) Attribute {
	attr := &attribute{
		name:  name,
		value: value,
	}
	return attr
}

// Name returns the attribute name.
func (attr *attribute) Name() string {
	return attr.name
}

// Value returns the attribute value.
func (attr *attribute) Value() string {
	return attr.value
}
