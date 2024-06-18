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

package gss

import (
	"testing"
)

func TestHeader(t *testing.T) {
	type expected struct {
		nonStdFlag bool
		cbFlag     CBFlag
		authID     string
	}

	tests := []struct {
		headerStr string
		expected  expected
	}{
		{
			headerStr: "n,,n=test,r=bDDLMhuQScihx0zXVXnizTplEBlE2ErT",
			expected: expected{
				nonStdFlag: false,
				cbFlag:     GS2ClientDoesNotSupportCBSFlag,
				authID:     "",
			},
		},
	}

	for _, test := range tests {
		header, err := NewHeaderFromString(test.headerStr)
		if err != nil {
			t.Error(err)
			continue
		}

		if header.NonStdFlag() != test.expected.nonStdFlag {
			t.Errorf("expected %v, got %v", test.expected.nonStdFlag, header.NonStdFlag())
		}

		if header.CBFlag() != test.expected.cbFlag {
			t.Errorf("expected %v, got %v", test.expected.cbFlag, header.CBFlag())
		}

		if header.AuthID() != test.expected.authID {
			t.Errorf("expected %v, got %v", test.expected.authID, header.AuthID())
		}
	}
}
