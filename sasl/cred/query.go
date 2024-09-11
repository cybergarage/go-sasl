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

// Query represents a query.
type Query struct {
	group    string
	username string
	password string
	opts     []any
}

// QueryOptionFn represents an option function for a query.
type QueryOptionFn func(*Query)

// QueryOption represents an option for a query.
type QueryOption any

// NewQuery returns a new query with options.
func NewQuery(opts ...QueryOptionFn) *Query {
	q := &Query{
		group:    "",
		username: "",
		password: "",
		opts:     []any{},
	}
	q.SetOption(opts...)
	return q
}

// WithQueryGroup returns an option to set the group.
func WithQueryGroup(group string) QueryOptionFn {
	return func(q *Query) {
		q.group = group
	}
}

// WithQueryUsername returns an option to set the username.
func WithQueryUsername(username string) QueryOptionFn {
	return func(q *Query) {
		q.username = username
	}
}

// WithQueryPassword returns an option to set the password.
func WithQueryPassword(password string) QueryOptionFn {
	return func(q *Query) {
		q.password = password
	}
}

// WithQueryOption returns an option to set the options.
func WithQueryOption(opt any) QueryOptionFn {
	return func(q *Query) {
		q.opts = append(q.opts, opt)
	}
}

// SetOption sets the options.
func (q *Query) SetOption(opts ...QueryOptionFn) {
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

// Options returns the options.
func (q *Query) Options() []any {
	return q.opts
}
