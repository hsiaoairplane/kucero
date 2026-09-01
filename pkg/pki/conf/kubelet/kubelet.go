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

package kubelet

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/hsiaoairplane/kucero/pkg/host"
	"github.com/hsiaoairplane/kucero/pkg/pki/conf"
)

type Kubelet struct {
	nodeName                        string
	enableKubeletClientCertRotation bool
	enableKubeletServerCertRotation bool
}

// New returns the kubelet instance
func New(nodeName string, enableKubeletClientCertRotation, enableKubeletServerCertRotation bool) conf.Config {
	return &Kubelet{
		nodeName:                        nodeName,
		enableKubeletClientCertRotation: enableKubeletClientCertRotation,
		enableKubeletServerCertRotation: enableKubeletServerCertRotation,
	}
}

func (k *Kubelet) CheckConfig() ([]string, error) {
	logrus.Infof("Commanding check %s node kubelet configuration", k.nodeName)

	var errs error
	var configsToBeUpdate []string
	for filepath, action := range configs {
		toUpdate, err := action.check(k, filepath)
		if err != nil {
			errs = fmt.Errorf("%w; ", err)
			continue
		}
		if toUpdate {
			configsToBeUpdate = append(configsToBeUpdate, filepath)
		}
	}

	return configsToBeUpdate, errs
}

func (k *Kubelet) UpdateConfig(configsToBeUpdate []string) error {
	var errs error
	for _, configToBeUpdate := range configsToBeUpdate {
		logrus.Infof("Commanding update %s node kubelet config path %s", k.nodeName, configToBeUpdate)

		action, ok := configs[configToBeUpdate]
		if !ok {
			return fmt.Errorf("map key %s does not exist", configToBeUpdate)
		}
		err := action.update(k, configToBeUpdate, configToBeUpdate)
		if err != nil {
			errs = fmt.Errorf("%w; ", err)
			continue
		}
	}
	if errs != nil {
		return errs
	}

	if err := host.RestartKubelet(k.nodeName); err != nil {
		errs = fmt.Errorf("%w; ", err)
	}

	return errs
}
