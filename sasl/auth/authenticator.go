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

// CredentialStoreRegistrar is the interface for setting the credential store.
type CredentialStoreRegistrar interface {
	// SetCredentialStore sets the credential store.
	SetCredentialStore(credStore CredentialStore)
}

// CredentialAuthenticator is the interface for authenticating a client using credential.
type CredentialAuthenticator interface {
	// VerifyCredential verifies the client credential.
	VerifyCredential(conn Conn, q Query) (bool, error)
}
