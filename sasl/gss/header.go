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

import "strings"

// Header represents a GS2 header.
type Header struct {
	props []string
}

// NewHeaderFromStrings creates a new header from the properties.
func NewHeaderFromStrings(props []string) (*Header, error) {
	header := &Header{
		props: []string{},
	}
	return header, header.Parse(props)
}

// NewHeaderFromString creates a new header from the properties string.
func NewHeaderFromString(props string) (*Header, error) {
	return NewHeaderFromStrings(strings.Split(props, ","))
}

// Parse parses the header properties.
func (header *Header) Parse(props []string) error {
	header.props = []string{}
	if len(props) < 2 {
		return ErrInvalidHeader
	}
	if props[0] != GS2NonStdFlag {
		header.props = append(header.props, GS2NonStdFlag)
		header.props = append(header.props, props[:1]...)
	} else {
		header.props = append(header.props, props[:2]...)
	}
	return nil
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

// AuthID returns the authorization identity.
func (header *Header) AuthID() string {
	return header.props[2]
}

// String returns the header properties.
func (header *Header) String() string {
	return strings.Join(header.props, ",")
}
