/*
Copyright 2026.

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

package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	authorinov1beta3 "github.com/kuadrant/authorino/api/v1beta3"
	kuadrantv1 "github.com/kuadrant/kuadrant-operator/api/v1"
	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
)

const gatewayKind = "Gateway"

// GatewayPolicyReconciler reconciles a Gateway object to generate AuthPolicies based on XAccessPolicies
type GatewayPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=agentic.networking.x-k8s.io,resources=xaccesspolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agentic.networking.x-k8s.io,resources=xaccesspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agentic.networking.x-k8s.io,resources=xaccesspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=kuadrant.io,resources=authpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *GatewayPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var gateway gatewayapiv1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gateway); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var policyList agenticv1alpha1.AccessPolicyList
	if err := r.List(ctx, &policyList, client.InNamespace(gateway.Namespace)); err != nil {
		return ctrl.Result{}, err
	}

	var allowPredicates []string
	var denyPredicates []string
	var targetPolicies []agenticv1alpha1.AccessPolicy

	for _, policy := range policyList.Items {
		if len(policy.Spec.TargetRefs) == 0 {
			continue
		}

		isTargetingGateway := false
		for _, targetRef := range policy.Spec.TargetRefs {
			if string(targetRef.Kind) == gatewayKind && string(targetRef.Name) == gateway.Name {
				isTargetingGateway = true
				break
			}
		}

		if !isTargetingGateway {
			continue
		}

		if string(policy.Spec.Action) == "ExternalAuth" {
			r.updateStatus(&policy, gateway.Name, "Accepted", metav1.ConditionFalse, "InvalidTarget", "UnsupportedFeature: ExternalAuth is not supported by this controller")
			_ = r.Status().Update(ctx, &policy)
			continue
		}

		targetPolicies = append(targetPolicies, policy)

		for _, rule := range policy.Spec.Rules {
			if rule.Source != nil && string(rule.Source.Type) == "SPIFFE" {
				continue
			}

			var ruleExpr string
			var authExpr string
			if rule.Authorization != nil {
				if string(rule.Authorization.Type) == "CEL" && rule.Authorization.CEL != nil {
					authExpr = rule.Authorization.CEL.Expression
					safeHeaderCheck := "(has(request.headers['x-mcp-toolname']) ? request.headers['x-mcp-toolname'] : '')"
					authExpr = strings.ReplaceAll(authExpr, "request.mcp.tool_name", safeHeaderCheck)
				} else if string(rule.Authorization.Type) == "Inline" && rule.Authorization.MCP != nil {
					var methodExprs []string
					for _, m := range rule.Authorization.MCP.Methods {
						if string(m.Name) == "tools/call" && len(m.Params) > 0 {
							methodExprs = append(methodExprs, fmt.Sprintf("has(request.headers['x-mcp-toolname']) && request.headers['x-mcp-toolname'] == '%s'", m.Params[0]))
						}
					}
					if len(methodExprs) > 0 {
						authExpr = strings.Join(methodExprs, " || ")
					}
				}
			}

			finalExpr := ""
			if ruleExpr != "" && authExpr != "" {
				finalExpr = fmt.Sprintf("(%s) && (%s)", ruleExpr, authExpr)
			} else if ruleExpr != "" {
				finalExpr = ruleExpr
			} else if authExpr != "" {
				finalExpr = authExpr
			} else {
				finalExpr = "true"
			}

			if string(policy.Spec.Action) == "Allow" || string(policy.Spec.Action) == "" {
				allowPredicates = append(allowPredicates, finalExpr)
			} else if string(policy.Spec.Action) == "Deny" {
				denyPredicates = append(denyPredicates, finalExpr)
			}
		}
	}

	if len(targetPolicies) == 0 {
		return ctrl.Result{}, nil
	}

	var combinedExpr string
	if len(allowPredicates) > 0 {
		allowExpr := strings.Join(allowPredicates, " || ")
		combinedExpr = fmt.Sprintf("(%s)", allowExpr)
	}
	if len(denyPredicates) > 0 {
		denyExpr := strings.Join(denyPredicates, " || ")
		if combinedExpr != "" {
			combinedExpr = fmt.Sprintf("%s && !(%s)", combinedExpr, denyExpr)
		} else {
			combinedExpr = fmt.Sprintf("!(%s)", denyExpr)
		}
	}

	var combinedPredicates []authorinov1beta3.PatternExpressionOrRef
	if combinedExpr != "" {
		combinedPredicates = append(combinedPredicates, authorinov1beta3.PatternExpressionOrRef{
			CelPredicate: authorinov1beta3.CelPredicate{
				Predicate: combinedExpr,
			},
		})
	}

	authPolicyName := fmt.Sprintf("%s-auth", gateway.Name)
	authPolicy := &kuadrantv1.AuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      authPolicyName,
			Namespace: gateway.Namespace,
		},
	}

	op, err := controllerutil.CreateOrPatch(ctx, r.Client, authPolicy, func() error {
		if authPolicy.Labels == nil {
			authPolicy.Labels = map[string]string{}
		}
		authPolicy.Labels["app.kubernetes.io/managed-by"] = "accesspolicy-controller"

		authPolicy.Spec.TargetRef = gatewayapiv1alpha2.LocalPolicyTargetReferenceWithSectionName{
			LocalPolicyTargetReference: gatewayapiv1alpha2.LocalPolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  gatewayKind,
				Name:  gatewayapiv1.ObjectName(gateway.Name),
			},
		}

		if authPolicy.Spec.AuthScheme == nil {
			authPolicy.Spec.AuthScheme = &kuadrantv1.AuthSchemeSpec{}
		}
		if authPolicy.Spec.AuthScheme.Authorization == nil {
			authPolicy.Spec.AuthScheme.Authorization = map[string]kuadrantv1.MergeableAuthorizationSpec{}
		}

		if len(combinedPredicates) > 0 {
			authPolicy.Spec.AuthScheme.Authorization["combined-rules"] = kuadrantv1.MergeableAuthorizationSpec{
				AuthorizationSpec: authorinov1beta3.AuthorizationSpec{
					AuthorizationMethodSpec: authorinov1beta3.AuthorizationMethodSpec{
						PatternMatching: &authorinov1beta3.PatternMatchingAuthorizationSpec{
							Patterns: combinedPredicates,
						},
					},
				},
			}
		} else {
			delete(authPolicy.Spec.AuthScheme.Authorization, "combined-rules")
		}

		return nil
	})

	if err != nil {
		for _, policy := range targetPolicies {
			p := policy
			r.updateStatus(&p, gateway.Name, "Programmed", metav1.ConditionFalse, "ProgramError", err.Error())
			_ = r.Status().Update(ctx, &p)
		}
		return ctrl.Result{}, err
	}

	log.Info("Reconciled AuthPolicy", "operation", op)

	for _, policy := range targetPolicies {
		p := policy
		r.updateStatus(&p, gateway.Name, "Programmed", metav1.ConditionTrue, "Programmed", "Successfully programmed Kuadrant AuthPolicy")
		r.updateStatus(&p, gateway.Name, "Accepted", metav1.ConditionTrue, "Accepted", "Policy accepted and valid")
		_ = r.Status().Update(ctx, &p)
	}

	return ctrl.Result{}, nil
}

func (r *GatewayPolicyReconciler) updateStatus(policy *agenticv1alpha1.AccessPolicy, gatewayName string, conditionType string, status metav1.ConditionStatus, reason, message string) {
	var ancestor *gatewayapiv1alpha2.PolicyAncestorStatus
	for i := range policy.Status.Ancestors {
		if string(policy.Status.Ancestors[i].AncestorRef.Name) == gatewayName {
			ancestor = &policy.Status.Ancestors[i]
			break
		}
	}

	if ancestor == nil {
		policy.Status.Ancestors = append(policy.Status.Ancestors, gatewayapiv1alpha2.PolicyAncestorStatus{
			AncestorRef: gatewayapiv1alpha2.ParentReference{
				Group: "gateway.networking.k8s.io",
				Kind:  gatewayKind,
				Name:  gatewayapiv1.ObjectName(gatewayName),
			},
		})
		ancestor = &policy.Status.Ancestors[len(policy.Status.Ancestors)-1]
	}

	meta.SetStatusCondition(&ancestor.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayapiv1.Gateway{}).
		Owns(&kuadrantv1.AuthPolicy{}).
		Watches(
			&agenticv1alpha1.AccessPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.findGatewaysForPolicy),
		).
		Complete(r)
}

func (r *GatewayPolicyReconciler) findGatewaysForPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
	policy, ok := obj.(*agenticv1alpha1.AccessPolicy)
	if !ok || len(policy.Spec.TargetRefs) == 0 {
		return nil
	}

	var requests []reconcile.Request
	for _, targetRef := range policy.Spec.TargetRefs {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      string(targetRef.Name),
				Namespace: policy.Namespace,
			},
		})
	}
	return requests
}
