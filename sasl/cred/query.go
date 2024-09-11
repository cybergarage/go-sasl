// Copyright (C) 2019 The go-sasl Authors. All rights reserved.
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

package cred

// Query represents a qential.
type Query struct {
	group    string
	username string
	password string
}

// QueryOption represents an option for a qential.
type QueryOption func(*Query)

// NewQuery returns a new qential with options.
func NewQuery(opts ...QueryOption) *Query {
	q := &Query{
		group:    "",
		username: "",
		password: "",
	}
	q.SetOption(opts...)
	return q
}

// WithGroup returns an option to set the group.
func WithQueryGroup(group string) QueryOption {
	return func(q *Query) {
		q.group = group
	}
}

// WithUsername returns an option to set the username.
func WithQueryUsername(username string) QueryOption {
	return func(q *Query) {
		q.username = username
	}
}

// WithPassword returns an option to set the password.
func WithQueryPassword(password string) QueryOption {
	return func(q *Query) {
		q.password = password
	}
}

// SetOption sets the options.
func (q *Query) SetOption(opts ...QueryOption) {
	for _, opt := range opts {
		opt(q)
	}
}

// Group returns the group.
func (q *Query) Group() string {
	return q.group
}

// Username returns the username.
func (q *Query) Username() string {
	return q.username
}

// Password returns the password.
func (q *Query) Password() string {
	return q.password
}
