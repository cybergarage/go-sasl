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

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// DefaultCredentialAuthenticator interface includes CredentialAuthenticator and CredentialStoreRegistrar interfaces.
type DefaultCredentialAuthenticator interface {
	CredentialAuthenticator
	CredentialStoreRegistrar
}

type defaultCredAuthenticator struct {
	credStore CredentialStore
}

// NewDefaultCredentialAuthenticator returns a new default credential authenticator.
func NewDefaultCredentialAuthenticator() DefaultCredentialAuthenticator {
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

	credPassword := cred.Password()
	encrypncryptFunc := q.EncryptFunc()
	if encrypncryptFunc != nil {
		credPassword, err = encrypncryptFunc(credPassword, q.Arguments()...)
		if err != nil {
			return false, err
		}
	}

	compareCredential := func(queryPassword any, credPassword any) bool {
		switch qp := queryPassword.(type) {
		case string:
			switch cp := credPassword.(type) {
			case string:
				return strings.Compare(qp, cp) == 0
			case []byte:
				if strings.Compare(qp, string(cp)) == 0 {
					return true
				}
				if strings.Compare(qp, hex.EncodeToString(cp)) == 0 {
					return true
				}
				return false
			}
		case []byte:
			switch cp := credPassword.(type) {
			case []byte:
				return bytes.Equal(qp, cp)
			case string:
				if bytes.Equal(qp, []byte(cp)) {
					return true
				}
				if strings.Compare(hex.EncodeToString(qp), cp) == 0 {
					return true
				}
				return false
			}
		}
		return false
	}

	return compareCredential(q.Password(), credPassword), nil
}
