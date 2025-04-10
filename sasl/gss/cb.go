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

// CBFlag represents a channel binding flag.
type CBFlag rune

const (
	ClientSupportsUsedCBSFlag   = CBFlag('p')
	ClientDoesNotSupportCBSFlag = CBFlag('n')
	ClientSupportsCBSFlag       = CBFlag('y')
)

// IsValid returns true if the flag is valid.
func (flag CBFlag) IsValid() bool {
	switch flag {
	case ClientSupportsUsedCBSFlag, ClientDoesNotSupportCBSFlag, ClientSupportsCBSFlag:
		return true
	}
	return false
}

// String returns a string representation of the flag.
func (flag CBFlag) String() string {
	return string(flag)
}
