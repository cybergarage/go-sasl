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

package xdg

import (
	"testing"
)

func TestPortabilityWithXdg(t *testing.T) {
	t.Run("xdg-go", func(t *testing.T) {
		t.Run("func", func(t *testing.T) {
			t.Run("SaltedPassword", func(t *testing.T) {
				SaltedPasswordTest(t)
			})
		})
		t.Run("client", func(t *testing.T) {
			ClientTestWithXdg(t)
		})
		t.Run("server", func(t *testing.T) {
			ServerTestWithXdg(t)
		})
	})
}
