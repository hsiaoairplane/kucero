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
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/version"

	"github.com/sirupsen/logrus"

	"github.com/jenting/kucero/pkg/host"
	"github.com/jenting/kucero/pkg/pki/clock"
)

// newKubeadmCmd returns a command that runs kubeadm with the given arguments.
// In unprivileged mode the binary is called directly; otherwise nsenter is
// used to enter the host mount namespace.
func newKubeadmCmd(arg ...string) *exec.Cmd {
	if host.IsUnprivileged() {
		// In unprivileged mode, kubeadm and the certificate paths are accessed
		// directly via host volume mounts instead of entering the host mount namespace.
		return host.NewCommandWithStdout("/usr/bin/kubeadm", arg...)
	}
	// Relies on hostPID:true and privileged:true to enter host mount space
	return host.NewCommandWithStdout("/usr/bin/nsenter", append([]string{"-m/proc/1/ns/mnt", "/usr/bin/kubeadm"}, arg...)...)
}

// kubeadmAlphaCertsCheckExpiration executes `kubeadm alpha certs check-expiration`
// returns the certificates which are going to expires
func kubeadmAlphaCertsCheckExpiration(expiryTimeToRotate time.Duration, clock clock.Clock) ([]string, error) {
	expiryCertificates := []string{}

	cmd := newKubeadmCmd("version", "-oshort")
	out, err := cmd.Output()
	if err != nil {
		logrus.Errorf("Error invoking %s: %v", cmd.Args, err)
		return expiryCertificates, err
	}

	// kubeadm >= 1.20.0: kubeadm certs check-expiration
	// otherwise: kubeadm alpha certs check-expiration
	ver := strings.TrimSuffix(string(out), "\n")
	if version.MustParseSemantic(ver).AtLeast(version.MustParseSemantic("v1.20.0")) {
		cmd = newKubeadmCmd("certs", "check-expiration")
	} else {
		cmd = newKubeadmCmd("alpha", "certs", "check-expiration")
	}
	stdout, err := cmd.Output()
	if err != nil {
		logrus.Errorf("Error invoking %s: %v", cmd.Args, err)
		return expiryCertificates, err
	}

	stdoutS := string(stdout)
	kv := parsekubeadmAlphaCertsCheckExpiration(stdoutS)
	for cert, t := range kv {
		expiry := checkCertificateExpiry(cert, t, expiryTimeToRotate, clock)
		if expiry {
			expiryCertificates = append(expiryCertificates, cert)
		}
	}

	return expiryCertificates, nil
}

func kubeadmAlphaCertsRenew(certificateName, certificatePath string) error {
	cmd := newKubeadmCmd("version", "-oshort")
	out, err := cmd.Output()
	if err != nil {
		logrus.Errorf("Error invoking %s: %v", cmd.Args, err)
		return err
	}

	// kubeadm >= 1.20.0: kubeadm certs renew <certificate-name>
	// otherwise: kubeadm alpha certs renew <certificate-name>
	ver := strings.TrimSuffix(string(out), "\n")
	if version.MustParseSemantic(ver).AtLeast(version.MustParseSemantic("v1.20.0")) {
		cmd = newKubeadmCmd("certs", "renew", certificateName)
	} else {
		cmd = newKubeadmCmd("alpha", "certs", "renew", certificateName)
	}
	return cmd.Run()
}

// parsekubeadmAlphaCertsCheckExpiration processes the `kubeadm alpha certs check-expiration`
// output and returns the certificate and expires information
func parsekubeadmAlphaCertsCheckExpiration(input string) map[string]time.Time {
	certExpires := make(map[string]time.Time)

	r := regexp.MustCompile("(.*) ([a-zA-Z]+ [0-9]{1,2}, [0-9]{4} [0-9]{1,2}:[0-9]{2} [a-zA-Z]+) (.*)")
	lines := strings.Split(input, "\n")
	parse := false
	for _, line := range lines {
		if parse {
			ss := r.FindStringSubmatch(line)
			if len(ss) < 3 {
				continue
			}

			cert := strings.TrimSpace(ss[1])
			t, err := time.Parse("Jan 02, 2006 15:04 MST", ss[2])
			if err != nil {
				fmt.Printf("err: %v\n", err)
				continue
			}

			certExpires[cert] = t
		}

		if strings.Contains(line, "CERTIFICATE") && strings.Contains(line, "EXPIRES") {
			parse = true
		}
	}

	return certExpires
}

// checkCertificateExpiry checks if the time `t` is less than the time duration `expiryTimeToRotate`
func checkCertificateExpiry(name string, t time.Time, expiryTimeToRotate time.Duration, clock clock.Clock) bool {
	tn := clock.Now()
	if t.Before(tn) {
		logrus.Infof("The certificate %s is expiry already", name)
		return true
	} else if t.Sub(tn) <= expiryTimeToRotate {
		logrus.Infof("The certificate %s notAfter is less than user specified expiry time %s", name, expiryTimeToRotate)
		return true
	}

	logrus.Infof("The certificate %s is still valid for %s", name, t.Sub(tn))
	return false
}
