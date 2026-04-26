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

package node

import (
	"time"

	"github.com/jenting/kucero/pkg/pki/cert"
	"github.com/jenting/kucero/pkg/pki/cert/kubeadm"
	"github.com/jenting/kucero/pkg/pki/cert/null"
	"github.com/jenting/kucero/pkg/pki/conf"
	"github.com/jenting/kucero/pkg/pki/conf/kubelet"
)

type Node struct {
	conf.Config      // configureation interface
	cert.Certificate // certificate interface
}

// New checks if it's a control plane node or worker node
// then returns the corresponding node interface
func New(isControlPlane bool, name string, expiryTimeToRotate time.Duration, enableKubeletClientCertRotation, enableKubeletServerCertRotation, enableCACertRotation bool) *Node {
	if isControlPlane {
		return &Node{
			Config:      kubelet.New(name, enableKubeletClientCertRotation, enableKubeletServerCertRotation),
			Certificate: kubeadm.New(name, expiryTimeToRotate, enableCACertRotation),
		}
	}
	return &Node{
		Config:      kubelet.New(name, enableKubeletClientCertRotation, enableKubeletServerCertRotation),
		Certificate: null.New(name, expiryTimeToRotate),
	}
}
