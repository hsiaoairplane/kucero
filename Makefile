MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:

# The semver version number which will be used as the Docker image tag
# Defaults to the output of git describe.
VERSION ?= $(shell git describe --tags --dirty --always)

# Docker image name parameters
IMG_NAME ?= jenting/kucero
IMG_TAG ?= ${VERSION}
IMG ?= ${IMG_NAME}:${IMG_TAG}

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

BIN := ${CURDIR}/bin
export PATH := ${BIN}:${PATH}

all: kucero

verify:
	go mod tidy
	go mod verify

test: verify
	go test -count=1 ./...

CLUSTER_NAME ?= kind

e2e-test: docker-build
	bash +x ./integration/test.sh ${IMG} ${CLUSTER_NAME}

kucero: test
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o cmd/kucero/kucero cmd/kucero/*.go

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Build the docker image
docker-build:
	docker build --build-arg VERSION=${VERSION} -t ${IMG} .

# Push the docker image
docker-push:
	docker push ${IMG}

# Deploy manifest
deploy-manifest:
	cd manifest && kustomize create --autodetect 2>/dev/null || true
	cd manifest && kustomize edit set image kucero=${IMG}
	kustomize build manifest | kubectl apply -f -

# Destroy manifest
destroy-manifest:
	cd manifest && kustomize create --autodetect 2>/dev/null || true
	kustomize build manifest | kubectl delete -f -

clean:
	go clean -x -i ./...
