// Copyright (C) 2024 The go-mysql Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

type defaultCredAuthenticator struct {
	credStore CredentialStore
}

// NewDefaultCredentialAuthenticator returns a new default credential authenticator.
func NewDefaultCredentialAuthenticator() CredentialAuthenticator {
	return &defaultCredAuthenticator{
		credStore: nil,
	}
}

func (ca *defaultCredAuthenticator) SetCredentialStore(credStore CredentialStore) {
	ca.credStore = credStore
}

// VerifyCredential verifies the client credential.
func (ca *defaultCredAuthenticator) VerifyCredential(conn Conn, q Query) (bool, error) {
	if ca.credStore == nil {
		return true, nil
	}
	cred, ok, err := ca.credStore.LookupCredential(q)
	if !ok {
		return false, err
	}
	if q.Username() != cred.Username() {
		return false, nil
	}
	if q.Password() != cred.Password() {
		return false, nil
	}
	return true, nil
}
