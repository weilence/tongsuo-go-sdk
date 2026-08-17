// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tongsuogo

import (
	"fmt"
	"os"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// LoadCertificateChainFromFile reads a PEM file and parses every certificate
// block in it, leaf first, remaining chain certificates after.
func LoadCertificateChainFromFile(path string) ([]*crypto.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate %q: %w", path, err)
	}
	blocks := SplitPEM(data)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("certificate %q contains no PEM certificates", path)
	}
	certs := make([]*crypto.Certificate, 0, len(blocks))
	for _, block := range blocks {
		cert, err := crypto.LoadCertificateFromPEM(block)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// LoadPrivateKeyFromFile reads a PEM file and parses the unencrypted private
// key in it.
func LoadPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key %q: %w", path, err)
	}
	key, err := crypto.LoadPrivateKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parsing unencrypted private key %q: %w", path, err)
	}
	return key, nil
}
