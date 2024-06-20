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
	"strings"

	"github.com/cybergarage/go-sasl/sasl/common"
)

// Header represents a GS2 header.
type Header struct {
	props []string
}

// NewHeader creates a new header.
func NewHeader() *Header {
	return &Header{
		props: []string{},
	}
}

// NewHeaderFromString creates a new header from the properties string.
func NewHeaderFromString(str string) (*Header, error) {
	header := NewHeader()
	return header, header.ParseString(str)
}

// NewHeaderFromString creates a new header from the properties strings.
func NewHeaderFromStrings(props []string) (*Header, error) {
	header := NewHeader()
	return header, header.ParseStrings(props)
}

// ParseString parses the header properties.
func (header *Header) ParseString(str string) error {
	return header.ParseStrings(strings.Split(str, ","))
}

// ParseStrings parses the header properties.
func (header *Header) ParseStrings(props []string) error {
	header.props = []string{}
	if len(props) < 2 {
		return ErrInvalidHeader
	}
	if props[0] != GS2NonStdFlag {
		header.props = append(header.props, "")
		header.props = append(header.props, props[:2]...)
	} else {
		header.props = append(header.props, props[:3]...)
	}
	if 0 < len(header.props[2]) {
		if !strings.HasPrefix(header.props[2], GS2AuthzidPrefix) {
			return ErrInvalidHeader
		}
	}
	return nil
}

// HasStdFlag returns true if the header has a standard flag.
func (header *Header) HasStdFlag() bool {
	return 0 < len(header.props[0])
}

// NonStdFlag returns true if the header has a non-standard flag.
func (header *Header) NonStdFlag() bool {
	return header.props[0] == GS2NonStdFlag
}

// CBFlag returns the channel binding flag.
func (header *Header) CBFlag() CBFlag {
	if len(header.props[1]) < 1 {
		return CBFlag(' ')
	}
	return CBFlag(header.props[1][0])
}

func (header *Header) CBName() string {
	if len(header.props[1]) < 2 {
		return ""
	}
	return header.props[1][2:]
}

// AuthzID returns the authorization identity.
func (header *Header) AuthzID() string {
	if len(header.props[2]) < len(GS2AuthzidPrefix) {
		return ""
	}
	return common.DecodeName(header.props[2][2:])
}

// String returns the header properties.
func (header *Header) String() string {
	return strings.Join(header.props, ",")
}
