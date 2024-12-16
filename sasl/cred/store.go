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

// Store represents a credential store.
type Store interface {
	// LookupCredential looks up a credential by the given query.
	//
	// Parameters:
	//   q - The query used to look up the credential.
	//
	// Returns:
	//   Credential - The credential associated with the query.
	//   bool - A boolean indicating whether the credential was found (true) or not (false).
	//   error - An error if there was an issue during the lookup process, or nil if the lookup was successful.
	//
	// If the credential is not found, the function returns an empty Credential, false, and nil error.
	// If an error occurs during the lookup process, the function returns an empty Credential, false, and the error.
	LookupCredential(q Query) (Credential, bool, error)
}
