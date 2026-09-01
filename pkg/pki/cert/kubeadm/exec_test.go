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

package kubeadm

import (
	"reflect"
	"testing"
	"time"

	"github.com/hsiaoairplane/kucero/pkg/pki/clock"
)

func Test_parseKubeadmCertsCheckExpiration(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]time.Time
	}{
		{
			name: "kubeadm 1.15.2 and 1.16.2",
			input: `
CERTIFICATE                EXPIRES                  RESIDUAL TIME   EXTERNALLY MANAGED
admin.conf                 May 12, 2021 02:29 UTC   364d            no
apiserver                  May 12, 2021 02:29 UTC   364d            no
apiserver-etcd-client      May 12, 2021 02:29 UTC   364d            no
apiserver-kubelet-client   May 12, 2021 02:29 UTC   364d            no
controller-manager.conf    May 12, 2021 02:29 UTC   364d            no
etcd-healthcheck-client    May 12, 2021 02:29 UTC   364d            no
etcd-peer                  May 12, 2021 02:29 UTC   364d            no
etcd-server                May 12, 2021 02:29 UTC   364d            no
front-proxy-client         May 12, 2021 02:29 UTC   364d            no
scheduler.conf             May 12, 2021 02:29 UTC   364d            no		
			`,
			expect: map[string]time.Time{
				"admin.conf":               time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver":                time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver-etcd-client":    time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver-kubelet-client": time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"controller-manager.conf":  time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-healthcheck-client":  time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-peer":                time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-server":              time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"front-proxy-client":       time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"scheduler.conf":           time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
			},
		},
		{
			name: "kubeadm 1.17.4",
			input: `
CERTIFICATE                EXPIRES                  RESIDUAL TIME   CERTIFICATE AUTHORITY   EXTERNALLY MANAGED
admin.conf                 May 12, 2021 02:29 UTC   364d                                    no
apiserver                  May 12, 2021 02:29 UTC   364d            ca                      no
apiserver-etcd-client      May 12, 2021 02:29 UTC   364d            etcd-ca                 no
apiserver-kubelet-client   May 12, 2021 02:29 UTC   364d            ca                      no
controller-manager.conf    May 12, 2021 02:29 UTC   364d                                    no
etcd-healthcheck-client    May 12, 2021 02:29 UTC   364d            etcd-ca                 no
etcd-peer                  May 12, 2021 02:29 UTC   364d            etcd-ca                 no
etcd-server                May 12, 2021 02:29 UTC   364d            etcd-ca                 no
front-proxy-client         May 12, 2021 02:29 UTC   364d            front-proxy-ca          no
scheduler.conf             May 12, 2021 02:29 UTC   364d                                    no

CERTIFICATE AUTHORITY   EXPIRES                  RESIDUAL TIME   EXTERNALLY MANAGED
ca                      Mar 11, 2030 01:51 UTC   9y              no
etcd-ca                 Mar 11, 2030 01:51 UTC   9y              no
front-proxy-ca          Mar 11, 2030 01:51 UTC   9y              no
					`,
			expect: map[string]time.Time{
				"admin.conf":               time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver":                time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver-etcd-client":    time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"apiserver-kubelet-client": time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"ca":                       time.Date(2030, time.March, 11, 01, 51, 00, 00, time.UTC),
				"controller-manager.conf":  time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-ca":                  time.Date(2030, time.March, 11, 01, 51, 00, 00, time.UTC),
				"etcd-healthcheck-client":  time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-peer":                time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"etcd-server":              time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"front-proxy-ca":           time.Date(2030, time.March, 11, 01, 51, 00, 00, time.UTC),
				"front-proxy-client":       time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
				"scheduler.conf":           time.Date(2021, time.May, 12, 02, 29, 00, 00, time.UTC),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := parsekubeadmAlphaCertsCheckExpiration(tt.input)
			if !reflect.DeepEqual(got, tt.expect) {
				t.Errorf("got %v is not equals to expected", got)
			}
		})
	}
}

type stubClock struct {
}

func newStubClock() clock.Clock {
	return &stubClock{}
}

func (s *stubClock) Now() time.Time {
	return time.Date(2000, time.January, 02, 03, 04, 05, 06, time.UTC)
}

func Test_checkExpiry(t *testing.T) {
	stubClock := newStubClock()

	tests := []struct {
		name                    string
		inputT                  time.Time
		inputExpiryTimeToRotate time.Duration
		expect                  bool
	}{
		{
			name:                    "expired certificate",
			inputT:                  time.Date(1960, time.May, 12, 02, 29, 00, 00, time.UTC),
			inputExpiryTimeToRotate: time.Minute,
			expect:                  true,
		},
		{
			name:                    "going to expire certificate",
			inputT:                  time.Date(2000, time.January, 02, 03, 05, 05, 06, time.UTC),
			inputExpiryTimeToRotate: time.Minute,
			expect:                  true,
		},
		{
			name:                    "still valid certificate",
			inputT:                  time.Date(2100, time.May, 12, 02, 29, 00, 00, time.UTC),
			inputExpiryTimeToRotate: time.Minute,
			expect:                  false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := checkCertificateExpiry(tt.name, tt.inputT, tt.inputExpiryTimeToRotate, stubClock)
			if !reflect.DeepEqual(got, tt.expect) {
				t.Errorf("got %t is not equals to expected %t", got, tt.expect)
			}
		})
	}
}
