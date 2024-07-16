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

import (
	"errors"
	"fmt"
)

// ErrInvalidMessage is returned when the message is invalid.
var ErrInvalidAttribute = errors.New("invalid attribute")

// ErrInvalidMessage is returned when the message is invalid.
var ErrInvalidMessage = errors.New("invalid message")

// ErrAuthorization is returned when the authorization is invalid.
var ErrAuthorization = errors.New("authorization error")

func newErrInvalidAttribute(attr string) error {
	return fmt.Errorf("%w : %s", ErrInvalidAttribute, attr)
}

func newErrInvalidMessage(msg string) error {
	return fmt.Errorf("%w : %s", ErrInvalidMessage, msg)
}

func newErrAuthorization(msg string) error {
	return fmt.Errorf("%w : %s", ErrAuthorization, msg)
}
