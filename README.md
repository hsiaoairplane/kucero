![CI](https://github.com/SUSE/kucero/workflows/CI/badge.svg)

![kucero](logo.png)

## Introduction

Kucero (KUbernetes CErtificate ROtation) is a Kubernetes daemonset that
performs _automatic_ Kubernetes control plane certificate rotation.

Kucero takes care both:
- kubeadm certificates and kubeconfigs: kucero periodically watches the kubeadm generated certificates and kubeconfigs on host system, and renews certificates/kubeconfigs when the certificates/kubeconfigs residual time is below than user configured time period.
- kubelet certificates:
  - kubelet.conf: kucero helps on auto-update the `/etc/kubernetes/kubelet.conf` from embedded base64 encoded client cert/key to using the local file `/var/lib/kubelet/kubelet-client-current.pem` (this is a bug if you bootstrap a cluster with kubeadm version < 1.17).
  - client certificate: kucero helps on configuring `rotateCertificates: true` or `rotateCertificates: false` in `/var/lib/kubelet/config.yaml` which controls to auto rotates the kubelet client certificate or not. When configures `rotateCertificates: true`, the kubelet sends out the client CSR at approximately 70%-90% of the total lifetime of the certificate, then the kube-controler-manager watches kubelet client CSR, and then auto signs and approves kubelet client certificates with Kubernetes cluster CA cert/key pair.
  - server certificate: kucero helps on configuring `serverTLSBootstrap: true` or `serverTLSBootstrap: false` in `/var/lib/kubelet/config.yaml` which controls to auto rotates the kubelet server certificate or not. When configures `serverTLSBootstrap: true`, the kubelet sends out the server CSR at approximately 70%-90% of the total lifetime of the certificate, then the kucero controller watches kubelet server CSR, and then auto signs and approves kubelet server certificates with user-specified CA cert/key pair.

## Kubelet Configuration

By default, kucero enables kubelet client `rotateCertificates: true` and server certificates `serverTLSBootstrap: true` auto rotation, you could disable it by passing flags to kucero:
- `--enable-kubelet-client-cert-rotation=false`
- `--enable-kubelet-server-cert-rotation=false`

## CA Certificate Rotation

By default, CA certificate rotation is **disabled** because it is a disruptive operation. When a CA certificate is rotated, all leaf certificates signed by that CA are also automatically renewed. The affected CA certificates and their dependent leaf certificates are:

| CA certificate | Dependent leaf certificates |
|---|---|
| `ca` | `apiserver`, `apiserver-kubelet-client` |
| `etcd-ca` | `apiserver-etcd-client`, `etcd-healthcheck-client`, `etcd-peer`, `etcd-server` |
| `front-proxy-ca` | `front-proxy-client` |

Before rotating a CA, kucero backs up both the `.crt` and `.key` files so the previous CA can be restored if needed.

To enable CA certificate rotation, pass the flag to kucero:
- `--enable-ca-cert-rotation=true`

> **Warning**: CA rotation replaces the CA key pair. All components that trust the old CA (kubelets, external clients, etc.) must be updated to trust the new CA. Review the [Kubernetes manual CA rotation documentation](https://kubernetes.io/docs/tasks/tls/manual-rotation-of-ca-certificates/) before enabling this feature.

## Build Requirements

- Golang >= 1.17
- Docker
- Kustomize

## Container Requirement Package

- /usr/bin/nsenter

## Kubeadm Compatibility

- kubeadm >= 1.15.0

## Installation

```
make docker-build IMG=<YOUR-DOCKER-REPOSITORY-IMAGE-NAME-TAG>
make docker-push IMG=<YOUR-DOCKER-REPOSITORY-IMAGE-NAME-TAG>
make deploy-manifest IMG=<YOUR-DOCKER-REPOSITORY-IMAGE-NAME-TAG>
```

## Configuration

The following arguments can be passed to kucero via the daemonset pod template:

```
Flags:
      --ca-cert-path string         sign CSR with this certificate file (default "/etc/kubernetes/pki/ca.crt")
      --ca-key-path string          sign CSR with this private key file (default "/etc/kubernetes/pki/ca.key")
      --ds-name string              name of daemonset on which to place lock (default "kucero")
      --ds-namespace string         namespace containing daemonset on which to place lock (default "kube-system")
      --enable-kucero-controller    enable kucero controller (default true)
  -h, --help                        help for kucero
      --leader-election-id string   the name of the configmap used to coordinate leader election between kucero-controllers (default "kucero-leader-election")
      --lock-annotation string      annotation in which to record locking node (default "caasp.suse.com/kucero-node-lock")
      --metrics-addr string         the address the metric endpoint binds to (default ":8080")
      --polling-period duration     certificate rotation check period (default 1h0m0s)
      --renew-before duration       rotates certificate before expiry is below (default 720h0m0s)
```

## Uninstallation

```
make destroy-manifest
```

## Demo

- kubeadm
  [![asciicast](https://asciinema.org/a/340053.svg)](https://asciinema.org/a/340053)
- kubelet
  [![asciicast](https://asciinema.org/a/340054.svg)](https://asciinema.org/a/340054)
