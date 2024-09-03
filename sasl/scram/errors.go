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
)

// ErrInvalidEncoding is returned when the encoding is invalid.
var ErrInvalidEncoding = errors.New("invalid-encoding")

// ErrExtensionsNotSupported is returned when the extensions are not supported.
var ErrExtensionsNotSupported = errors.New("extensions-not-supported")

// ErrInvalidProof is returned when the proof is invalid.
var ErrInvalidProof = errors.New("invalid-proof")

// ErrChannelBindingsDontMatch is returned when the channel bindings don't match.
var ErrChannelBindingsDontMatch = errors.New("channel-bindings-dont-match")

// ErrServerDoesSupportChannelBinding is returned when the server does not support channel binding.
var ErrServerDoesSupportChannelBinding = errors.New("server-does-not-support-channel-binding")

// ErrChannelBindingNotSupported is returned when the channel binding is not supported.
var ErrChannelBindingNotSupported = errors.New("channel-binding-not-supported")

// ErrUnsupportedChannelBindingType is returned when the channel binding type is unsupported.
var ErrUnsupportedChannelBindingType = errors.New("unsupported-channel-binding-type")

// ErrUnknownUser is returned when the user is unknown.
var ErrUnknownUser = errors.New("unknown-user")

// ErrInvalidUsernameEncoding is returned when the username encoding is invalid.
var ErrInvalidUsernameEncoding = errors.New("invalid-username-encoding")

// ErrNoResources is returned when there are no resources.
var ErrNoResources = errors.New("no-resources")

// ErrOtherError is returned when there is another error.
var ErrOtherError = errors.New("other-error")
