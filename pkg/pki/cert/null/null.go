/*
Copyright (c) 2020 SUSE LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package null

import (
	"time"

	"github.com/hsiaoairplane/kucero/pkg/pki/cert"
)

type Null struct {
}

// New returns the kubeadm instance
func New(nodeName string, expiryTimeToRotate time.Duration) cert.Certificate {
	return &Null{}
}

// CheckExpiration returns empty slice string array and nil
func (n *Null) CheckExpiration() ([]string, error) {
	return []string{}, nil
}

// Rotate returns nil
func (n *Null) Rotate(expiryCertificates []string) error {
	return nil
}
