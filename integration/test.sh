#!/bin/bash

set -o pipefail
set -e

IMG=$1
CLUSTER_NAME=${2:-kind}

clean_up() {
	(cd manifest && kustomize create --autodetect 2>/dev/null || true)
	kustomize build manifest | kubectl --context kind-${CLUSTER_NAME} delete -f - 2>/dev/null || true
	[ -f manifest/kustomization.yaml ] && rm manifest/kustomization.yaml
}

trap clean_up EXIT

if ! command -v docker; then
    echo "docker could not be found"
    exit 1
fi

if ! command -v kind; then
    echo "kind could not be found"
    exit 1
fi

if ! command -v kustomize; then
    echo "kustomize could not be found"
    exit 1
fi

if ! command -v kubectl; then
    echo "kubectl could not be found"
    exit 1
fi

# Create KIND cluster if it does not already exist
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
	kind create cluster --name ${CLUSTER_NAME}
fi

# Find KIND cluster control-plane container by cluster label
TAG=$(docker ps --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --filter "label=io.x-k8s.kind.role=control-plane" --format "{{.ID}}")
if [ -z "${TAG}" ]; then
    echo "ERROR: could not find control-plane container for KIND cluster '${CLUSTER_NAME}'"
    exit 1
fi

# Load docker image into KIND cluster
kind load docker-image ${IMG} --name ${CLUSTER_NAME}

# Generate kustomization.yaml
(cd manifest && kustomize create --autodetect || true)

# Apply kustomize patch
cat << EOF >> manifest/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patchesStrategicMerge:
- |-
  apiVersion: apps/v1
  kind: DaemonSet
  metadata:
    name: kucero
    namespace: kube-system
  spec:
    template:
      spec:
        containers:
        - name: kucero
          image: ${IMG}
          args:
          - --polling-period=1m
          - --renew-before=8761h
          - --enable-kubelet-csr-controller=true
          - --enable-kubelet-server-cert-rotation=false
EOF
kustomize build manifest | kubectl --context kind-${CLUSTER_NAME} apply -f -

APISERVER_ETCD_CLIENT_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver-etcd-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
APISERVER_KUBELET_CLIENT_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver-kubelet-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
APISERVER_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver.crt -nocert -enddate | awk -F'=' '{print $2}'`
FRONT_PROXY_CLIENT_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/front-proxy-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_HEALTHCHECK_CLIENT_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/healthcheck-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_PEER_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/peer.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_SERVER_WAS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -nocert -enddate | awk -F'=' '{print $2}'`

kubectl --context kind-${CLUSTER_NAME} wait pods --for=condition=ready -n kube-system --all --timeout=3m
sleep 3m

APISERVER_ETCD_CLIENT_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver-etcd-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
APISERVER_KUBELET_CLIENT_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver-kubelet-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
APISERVER_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/apiserver.crt -nocert -enddate | awk -F'=' '{print $2}'`
FRONT_PROXY_CLIENT_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/front-proxy-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_HEALTHCHECK_CLIENT_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/healthcheck-client.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_PEER_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/peer.crt -nocert -enddate | awk -F'=' '{print $2}'`
ETCD_SERVER_IS=`docker exec -t ${TAG} openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -nocert -enddate | awk -F'=' '{print $2}'`

if [ "${APISERVER_ETCD_CLIENT_WAS}" = "${APISERVER_ETCD_CLIENT_IS}" ]; then
	echo "ERROR: apiserver-etcd-client.crt not renewed"
	exit 1
else
	echo "PASS: apiserver-etcd-client.crt renewed"
fi
if [ "${APISERVER_KUBELET_CLIENT_WAS}" = "${APISERVER_KUBELET_CLIENT_IS}" ]; then
	echo "ERROR: apiserver-kubelet-client.crt not renewed"
	exit 1
else
	echo "PASS: apiserver-kubelet-client.crt renewed"
fi
if [ "${APISERVER_WAS}" = "${APISERVER_IS}" ]; then
	echo "ERROR: apiserver.crt not renewed"
	exit 1
else
	echo "PASS: apiserver.crt renewed"
fi
if [ "${FRONT_PROXY_CLIENT_WAS}" = "${FRONT_PROXY_CLIENT_IS}" ]; then
	echo "ERROR: front-proxy-client.crt not renewed"
	exit 1
else
	echo "PASS: front-proxy-client.crt renewed"
fi
if [ "${ETCD_HEALTHCHECK_CLIENT_WAS}" = "${ETCD_HEALTHCHECK_CLIENT_IS}" ]; then
	echo "ERROR: etcd/healthcheck-client.crt not renewed"
	exit 1
else
	echo "PASS: etcd/healthcheck-client.crt renewed"
fi
if [ "${ETCD_PEER_WAS}" = "${ETCD_PEER_IS}" ]; then
	echo "ERROR: etcd/peer.crt not renewed"
	exit 1
else
	echo "PASS: etcd/peer.crt renewed"
fi
if [ "${ETCD_SERVER_WAS}" = "${ETCD_SERVER_IS}" ]; then
	echo "ERROR: etcd/server.crt not renewed"
	exit 1
else
	echo "PASS: etcd/server.crt renewed"
fi
