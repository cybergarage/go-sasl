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

package auth

// query represents a query.
type query struct {
	group       string
	username    string
	password    string
	mech        string
	opts        []any
	args        []any
	encryptFunc EncryptFunc
}

// QueryOptionFn represents an option function for a query.
type QueryOptionFn func(*query)

// QueryOption represents an option for a query.
type QueryOption any

// NewQuery returns a new query with options.
func NewQuery(opts ...QueryOptionFn) Query {
	q := &query{
		group:       "",
		username:    "",
		password:    "",
		mech:        "",
		opts:        []any{},
		args:        []any{},
		encryptFunc: nil,
	}
	q.SetOption(opts...)
	return q
}

// WithQueryGroup returns an option to set the group.
func WithQueryGroup(group string) QueryOptionFn {
	return func(q *query) {
		q.group = group
	}
}

// WithQueryUsername returns an option to set the username.
func WithQueryUsername(username string) QueryOptionFn {
	return func(q *query) {
		q.username = username
	}
}

// WithQueryPassword returns an option to set the password.
func WithQueryPassword(password string) QueryOptionFn {
	return func(q *query) {
		q.password = password
	}
}

// WithQueryMechanism returns an option to set the mechanism.
func WithQueryMechanism(mech string) QueryOptionFn {
	return func(q *query) {
		q.mech = mech
	}
}

// WithQueryOptions returns an option to set the options.
func WithQueryOptions(opt ...any) QueryOptionFn {
	return func(q *query) {
		q.opts = append(q.opts, opt...)
	}
}

// WithQueryArguments returns an option to set the arguments for the encrypt function.
func WithQueryArguments(args ...any) QueryOptionFn {
	return func(q *query) {
		q.args = append(q.args, args...)
	}
}

// SetOption sets the options.
func (q *query) SetOption(opts ...QueryOptionFn) {
	for _, opt := range opts {
		opt(q)
	}
}

// Group returns the group.
func (q *query) Group() string {
	return q.group
}

// Username returns the username.
func (q *query) Username() string {
	return q.username
}

// Password returns the password.
func (q *query) Password() string {
	return q.password
}

// Mechanism returns the mechanism.
func (q *query) Mechanism() string {
	return q.mech
}

// Options returns the options.
func (q *query) Options() []any {
	return q.opts
}

// EncryptFunc returns the encrypt function.
func (q *query) EncryptFunc() EncryptFunc {
	return q.encryptFunc
}

// Arguments returns the arguments for the encrypt function.
func (q *query) Arguments() []any {
	return q.args
}
