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

package util

import (
	"testing"
)

func TestName(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{"", ""},
		{"=", "=3D"},
		{";", "=2C"},
		{"=;", "=3D=2C"},
		{";=", "=2C=3D"},
		{"=;", "=3D=2C"},
		{";=", "=2C=3D"},
		{"=;=", "=3D=2C=3D"},
		{";=;", "=2C=3D=2C"},
		{"=;=", "=3D=2C=3D"},
		{";=;", "=2C=3D=2C"},
		{"a", "a"},
		{"a=", "a=3D"},
		{"a;", "a=2C"},
		{"a=;", "a=3D=2C"},
		{"a;=", "a=2C=3D"},
		{"a=;", "a=3D=2C"},
		{"a;=", "a=2C=3D"},
		{"a=;=", "a=3D=2C=3D"},
		{"a;=;", "a=2C=3D=2C"},
		{"a=;=", "a=3D=2C=3D"},
		{"a;=;", "a=2C=3D=2C"},
		{"b", "b"},
		{"=b", "=3Db"},
		{";b", "=2Cb"},
		{"=;b", "=3D=2Cb"},
		{";=b", "=2C=3Db"},
		{"=;b", "=3D=2Cb"},
		{";=b", "=2C=3Db"},
		{"=;=b", "=3D=2C=3Db"},
		{";=;b", "=2C=3D=2Cb"},
		{"=;=b", "=3D=2C=3Db"},
		{";=;b", "=2C=3D=2Cb"},
		{"ab", "ab"},
		{"a=b", "a=3Db"},
		{"a;b", "a=2Cb"},
		{"a=;b", "a=3D=2Cb"},
		{"a;=b", "a=2C=3Db"},
		{"a=;b", "a=3D=2Cb"},
		{"a;=b", "a=2C=3Db"},
		{"a=;=b", "a=3D=2C=3Db"},
		{"a;=;b", "a=2C=3D=2Cb"},
		{"a=;=b", "a=3D=2C=3Db"},
		{"a;=;b", "a=2C=3D=2Cb"},
	}

	for _, test := range tests {
		if got := EncodeName(test.in); got != test.out {
			t.Errorf("EncodeName(%q) = %q; want %q", test.in, got, test.out)
		}
		if got := DecodeName(test.out); got != test.in {
			t.Errorf("DecodeName(%q) = %q; want %q", test.out, got, test.in)
		}
	}
}
