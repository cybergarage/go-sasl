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

const (
	AuthorizationIDAttr     = "a"
	UserNameAttr            = "n"
	FutureExtensibilityAttr = "m"
	RandomSequenceAttr      = "r"
	ChannelBindingDataAttr  = "c"
	SaltAttr                = "s"
	IterationCountAttr      = "i"
	ClientProofAttr         = "p"
	ServerSignatureAttr     = "v"
	ErrorAttr               = "e"
)

const (
	initialRandomSequenceLength    = 24
	additionalRandomSequenceLength = 16
	defaultIterationCount          = minimumIterationCount
	minimumIterationCount          = 4096
	defaultSaltLength              = 16
)
