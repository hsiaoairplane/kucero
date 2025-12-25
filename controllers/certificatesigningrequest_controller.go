/*
Copyright 2020 The cert-manager authors.

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

package controllers

import (
	"context"
	"crypto/x509"
	"fmt"

	authorization "k8s.io/api/authorization/v1"
	capi "k8s.io/api/certificates/v1"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/sirupsen/logrus"

	"github.com/jenting/kucero/pkg/pki/cert"
	"github.com/jenting/kucero/pkg/pki/signer"
)

// CertificateSigningRequestSigningReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestSigningReconciler struct {
	Client        client.Client
	ClientSet     k8sclient.Interface
	Scheme        *runtime.Scheme
	Signer        *signer.Signer
	EventRecorder record.EventRecorder
}

// Tries to recognize CSRs that are specific to this use case
type csrRecognizer struct {
	recognize      func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
	permission     authorization.ResourceAttributes
	successMessage string
}

func recognizers() []csrRecognizer {
	recognizers := []csrRecognizer{
		{
			recognize:      isNodeServingCert,
			permission:     authorization.ResourceAttributes{Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create"},
			successMessage: "Auto approving kubelet serving certificate after SubjectAccessReview.",
		},
	}
	return recognizers
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *CertificateSigningRequestSigningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var csr capi.CertificateSigningRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &csr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, fmt.Errorf("error %q getting CSR", err)
	}
	switch {
	case !csr.DeletionTimestamp.IsZero():
		logrus.Info("CSR has been deleted. Ignoring")
	case csr.Status.Certificate != nil:
		logrus.Info("CSR has already been signed. Ignoring")
	default:
		logrus.Info("Signing")
		x509cr, err := cert.ParseCSR(csr.Spec.Request)
		if err != nil {
			logrus.Errorf("Unable to parse csr: %v", err)
			r.EventRecorder.Event(&csr, corev1.EventTypeWarning, "SigningFailed", "Unable to parse the CSR request")
			return ctrl.Result{}, nil
		}

		tried := []string{}
		for _, recognizer := range recognizers() {
			tried = append(tried, recognizer.permission.Resource)

			if !recognizer.recognize(&csr, x509cr) {
				continue
			}

			approved, err := r.authorize(&csr, recognizer.permission)
			if err != nil {
				logrus.Errorf("SubjectAccessReview failed: %v", err)
				return ctrl.Result{}, fmt.Errorf("error SubjectAccessReview: %v", err)
			}

			if approved {
				logrus.Infof("CSR: %v", csr.ObjectMeta.Name)
				logrus.Infof("X509v3 SAN DNS: %v", x509cr.DNSNames)
				logrus.Infof("X509v3 SAN IP: %v", x509cr.IPAddresses)
				logrus.Info("Approving csr")

				// sign the csr before approve
				// otherwise, the kube-controller-manager will sign the csr
				cert, err := r.Signer.Sign(x509cr, csr.Spec)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("error auto signing csr: %v", err)
				}
				patch := client.MergeFrom(csr.DeepCopy())
				csr.Status.Certificate = cert
				if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
					return ctrl.Result{}, fmt.Errorf("error patching CSR: %v", err)
				}

				// approve the csr
				appendApprovalCondition(&csr, recognizer.successMessage)
				_, err = r.ClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), csr.Name, &csr, metav1.UpdateOptions{})
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("error updating approval for csr: %v", err)
				}

				r.EventRecorder.Event(&csr, corev1.EventTypeNormal, "Signed", "The CSR has been signed")
			} else {
				return ctrl.Result{}, fmt.Errorf("SubjectAccessReview failed")
			}
		}
	}
	return ctrl.Result{}, nil
}

// Validate that the given node has authorization to actualy create CSRs
func (r *CertificateSigningRequestSigningReconciler) authorize(csr *capi.CertificateSigningRequest, rattrs authorization.ResourceAttributes) (bool, error) {
	extra := make(map[string]authorization.ExtraValue)
	for k, v := range csr.Spec.Extra {
		extra[k] = authorization.ExtraValue(v)
	}

	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			User:               csr.Spec.Username,
			UID:                csr.Spec.UID,
			Groups:             csr.Spec.Groups,
			Extra:              extra,
			ResourceAttributes: &rattrs,
		},
	}
	sar, err := r.ClientSet.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return sar.Status.Allowed, nil
}

func appendApprovalCondition(csr *capi.CertificateSigningRequest, message string) {
	csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
		Type:           capi.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "AutoApproved by kucero",
		Message:        message,
		LastUpdateTime: metav1.Now(),
	})
}

func (r *CertificateSigningRequestSigningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	discoveryClient := r.ClientSet.Discovery()

	// Query API server for certificates.k8s.io
	apiGroup, err := discoveryClient.ServerResourcesForGroupVersion("certificates.k8s.io/v1")
	if err == nil {
		for _, res := range apiGroup.APIResources {
			if res.Name == "certificatesigningrequests" {
				return ctrl.NewControllerManagedBy(mgr).
					For(&capi.CertificateSigningRequest{}).
					Complete(r)
			}
		}
	}

	// Fallback to v1beta1
	apiGroup, err = discoveryClient.ServerResourcesForGroupVersion("certificates.k8s.io/v1beta1")
	if err == nil {
		for _, res := range apiGroup.APIResources {
			if res.Name == "certificatesigningrequests" {
				return ctrl.NewControllerManagedBy(mgr).
					For(&capiv1beta1.CertificateSigningRequest{}).
					Complete(r)
			}
		}
	}

	return fmt.Errorf("unsupported certificates.k8s.io API version")
}
