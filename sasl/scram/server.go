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

// NewServerFirstMessageFrom returns a new server first message from the specified client message.
func NewServerFirstMessageFrom(clientMsg *Message) (*Message, error) {
	msg := NewMessage()
	return msg, nil
}

// NewServerFinalMessageFrom returns a new server final message from the specified client message.
func NewServerFinalMessageFrom(clientMsg *Message) (*Message, error) {
	msg := NewMessage()
	return msg, nil
}