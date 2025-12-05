//go:build integration && ginkgo
// +build integration,ginkgo

/*
Copyright 2025 Guided Traffic.

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

package integration

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/guided-traffic/internal-secrets-operator/pkg/replicator"
)

var _ = Describe("Secret Replication", func() {
	const timeout = time.Second * 30
	const interval = time.Millisecond * 250

	Context("Pull-based Replication", func() {
		It("should replicate from source to target with mutual consent", func() {
			ctx := context.Background()

			// Create source namespace
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "replication-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			// Create target namespace
			targetNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "replication-target",
				},
			}
			Expect(k8sClient.Create(ctx, targetNS)).Should(Succeed())

			// Create source Secret with allowlist
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-test-secret",
					Namespace: "replication-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "replication-target",
					},
				},
				Data: map[string][]byte{
					"username": []byte("testuser"),
					"password": []byte("testpass"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Create target Secret with replicate-from
			targetSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-test-secret",
					Namespace: "replication-target",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "replication-source/pull-test-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, targetSecret)).Should(Succeed())

			// Wait for replication to occur
			Eventually(func() bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "replication-target",
					Name:      "pull-test-secret",
				}, secret)
				if err != nil {
					return false
				}

				// Check if data was replicated
				return string(secret.Data["username"]) == "testuser" &&
					string(secret.Data["password"]) == "testpass" &&
					secret.Annotations[replicator.AnnotationReplicatedFrom] == "replication-source/pull-test-secret"
			}, timeout, interval).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetNS)).Should(Succeed())
		})

		It("should deny replication when target not in allowlist", func() {
			ctx := context.Background()

			// Create namespaces
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "replication-denied-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			unauthorizedNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "replication-unauthorized",
				},
			}
			Expect(k8sClient.Create(ctx, unauthorizedNS)).Should(Succeed())

			// Create source Secret with limited allowlist
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "denied-secret",
					Namespace: "replication-denied-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "other-namespace",
					},
				},
				Data: map[string][]byte{
					"secret": []byte("data"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Create target Secret trying to replicate
			targetSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "denied-secret",
					Namespace: "replication-unauthorized",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "replication-denied-source/denied-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, targetSecret)).Should(Succeed())

			// Wait a bit and verify data was NOT replicated
			Consistently(func() bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "replication-unauthorized",
					Name:      "denied-secret",
				}, secret)
				if err != nil {
					return false
				}

				// Data should NOT be present
				return len(secret.Data) == 0
			}, time.Second*5, interval).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, unauthorizedNS)).Should(Succeed())
		})

		It("should support wildcard patterns in allowlist", func() {
			ctx := context.Background()

			// Create source namespace
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wildcard-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			// Create multiple target namespaces matching pattern
			target1NS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "env-staging",
				},
			}
			Expect(k8sClient.Create(ctx, target1NS)).Should(Succeed())

			target2NS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "env-development",
				},
			}
			Expect(k8sClient.Create(ctx, target2NS)).Should(Succeed())

			// Create source Secret with wildcard allowlist
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcard-secret",
					Namespace: "wildcard-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicatableFromNamespaces: "env-*",
					},
				},
				Data: map[string][]byte{
					"data": []byte("wildcard-test"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Create target Secrets
			target1 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcard-secret",
					Namespace: "env-staging",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "wildcard-source/wildcard-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, target1)).Should(Succeed())

			target2 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wildcard-secret",
					Namespace: "env-development",
					Annotations: map[string]string{
						replicator.AnnotationReplicateFrom: "wildcard-source/wildcard-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, target2)).Should(Succeed())

			// Wait for both to be replicated
			Eventually(func() bool {
				secret1 := &corev1.Secret{}
				err1 := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "env-staging",
					Name:      "wildcard-secret",
				}, secret1)

				secret2 := &corev1.Secret{}
				err2 := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "env-development",
					Name:      "wildcard-secret",
				}, secret2)

				return err1 == nil && err2 == nil &&
					string(secret1.Data["data"]) == "wildcard-test" &&
					string(secret2.Data["data"]) == "wildcard-test"
			}, timeout, interval).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, target1)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, target2)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, target1NS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, target2NS)).Should(Succeed())
		})
	})

	Context("Push-based Replication", func() {
		It("should push Secret to target namespaces", func() {
			ctx := context.Background()

			// Create namespaces
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "push-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			targetNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "push-target",
				},
			}
			Expect(k8sClient.Create(ctx, targetNS)).Should(Succeed())

			// Create source Secret with replicate-to
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "push-secret",
					Namespace: "push-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "push-target",
					},
				},
				Data: map[string][]byte{
					"key": []byte("pushed-value"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Wait for Secret to be created in target namespace
			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "push-target",
					Name:      "push-secret",
				}, targetSecret)

				return err == nil &&
					string(targetSecret.Data["key"]) == "pushed-value" &&
					targetSecret.Annotations[replicator.AnnotationReplicatedFrom] == "push-source/push-secret"
			}, timeout, interval).Should(BeTrue())

			// Cleanup
			targetSecret := &corev1.Secret{}
			k8sClient.Get(ctx, types.NamespacedName{
				Namespace: "push-target",
				Name:      "push-secret",
			}, targetSecret)
			Expect(k8sClient.Delete(ctx, targetSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetNS)).Should(Succeed())
		})

		It("should update pushed Secret when source changes", func() {
			ctx := context.Background()

			// Create namespaces
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "update-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			targetNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "update-target",
				},
			}
			Expect(k8sClient.Create(ctx, targetNS)).Should(Succeed())

			// Create source Secret
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "update-secret",
					Namespace: "update-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "update-target",
					},
				},
				Data: map[string][]byte{
					"version": []byte("v1"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Wait for initial push
			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "update-target",
					Name:      "update-secret",
				}, targetSecret)
				return err == nil && string(targetSecret.Data["version"]) == "v1"
			}, timeout, interval).Should(BeTrue())

			// Update source Secret
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Namespace: "update-source",
				Name:      "update-secret",
			}, sourceSecret)).Should(Succeed())

			sourceSecret.Data["version"] = []byte("v2")
			Expect(k8sClient.Update(ctx, sourceSecret)).Should(Succeed())

			// Wait for update to propagate
			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "update-target",
					Name:      "update-secret",
				}, targetSecret)
				return err == nil && string(targetSecret.Data["version"]) == "v2"
			}, timeout, interval).Should(BeTrue())

			// Cleanup
			targetSecret := &corev1.Secret{}
			k8sClient.Get(ctx, types.NamespacedName{
				Namespace: "update-target",
				Name:      "update-secret",
			}, targetSecret)
			Expect(k8sClient.Delete(ctx, targetSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetNS)).Should(Succeed())
		})

		It("should cleanup pushed Secrets when source is deleted", func() {
			ctx := context.Background()

			// Create namespaces
			sourceNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cleanup-source",
				},
			}
			Expect(k8sClient.Create(ctx, sourceNS)).Should(Succeed())

			targetNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cleanup-target",
				},
			}
			Expect(k8sClient.Create(ctx, targetNS)).Should(Succeed())

			// Create source Secret
			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cleanup-secret",
					Namespace: "cleanup-source",
					Annotations: map[string]string{
						replicator.AnnotationReplicateTo: "cleanup-target",
					},
				},
				Data: map[string][]byte{
					"data": []byte("test"),
				},
			}
			Expect(k8sClient.Create(ctx, sourceSecret)).Should(Succeed())

			// Wait for push
			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "cleanup-target",
					Name:      "cleanup-secret",
				}, targetSecret)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			// Delete source Secret
			Expect(k8sClient.Delete(ctx, sourceSecret)).Should(Succeed())

			// Wait for pushed Secret to be deleted
			Eventually(func() bool {
				targetSecret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "cleanup-target",
					Name:      "cleanup-secret",
				}, targetSecret)
				return err != nil // Should not exist
			}, timeout, interval).Should(BeTrue())

			// Cleanup namespaces
			Expect(k8sClient.Delete(ctx, sourceNS)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, targetNS)).Should(Succeed())
		})
	})

	Context("Feature Interactions", func() {
		It("should reject Secrets with both autogenerate and replicate-from", func() {
			ctx := context.Background()

			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "conflict-test",
				},
			}
			Expect(k8sClient.Create(ctx, ns)).Should(Succeed())

			// Create Secret with conflicting annotations
			conflictSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "conflict-secret",
					Namespace: "conflict-test",
					Annotations: map[string]string{
						"iso.gtrfc.com/autogenerate":       "password",
						replicator.AnnotationReplicateFrom: "other-ns/other-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, conflictSecret)).Should(Succeed())

			// Secret should remain unchanged (no data generated or replicated)
			Consistently(func() bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "conflict-test",
					Name:      "conflict-secret",
				}, secret)
				return err == nil && len(secret.Data) == 0
			}, time.Second*5, interval).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, conflictSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, ns)).Should(Succeed())
		})

		It("should allow autogenerate and replicatable-from-namespaces together", func() {
			ctx := context.Background()

			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "combined-test",
				},
			}
			Expect(k8sClient.Create(ctx, ns)).Should(Succeed())

			// Create Secret with both autogenerate and replicatable-from-namespaces
			combinedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "combined-secret",
					Namespace: "combined-test",
					Annotations: map[string]string{
						"iso.gtrfc.com/autogenerate":                    "password",
						replicator.AnnotationReplicatableFromNamespaces: "*",
					},
				},
			}
			Expect(k8sClient.Create(ctx, combinedSecret)).Should(Succeed())

			// Should work fine - autogenerate creates data, replicatable allows sharing
			Eventually(func() bool {
				secret := &corev1.Secret{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: "combined-test",
					Name:      "combined-secret",
				}, secret)
				return err == nil && len(secret.Data) > 0 &&
					secret.Annotations[replicator.AnnotationReplicatableFromNamespaces] == "*"
			}, timeout, interval).Should(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, combinedSecret)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, ns)).Should(Succeed())
		})
	})
})
