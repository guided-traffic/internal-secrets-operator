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

package replicator

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ReplicateConfigMap copies data from source ConfigMap to target ConfigMap
func ReplicateConfigMap(source, target *corev1.ConfigMap) {
	if target.Data == nil {
		target.Data = make(map[string]string)
	}
	for key, value := range source.Data {
		target.Data[key] = value
	}

	if len(source.BinaryData) > 0 && target.BinaryData == nil {
		target.BinaryData = make(map[string][]byte)
	}
	for key, value := range source.BinaryData {
		target.BinaryData[key] = value
	}

	if target.Annotations == nil {
		target.Annotations = make(map[string]string)
	}
	target.Annotations[AnnotationReplicatedFrom] = fmt.Sprintf("%s/%s", source.Namespace, source.Name)
	target.Annotations[AnnotationLastReplicatedAt] = time.Now().Format(time.RFC3339)
}

// IsConfigMapBeingDeleted checks if a ConfigMap is being deleted (has DeletionTimestamp)
func IsConfigMapBeingDeleted(cm *corev1.ConfigMap) bool {
	return !cm.DeletionTimestamp.IsZero()
}
