// (C) Copyright Confidential Containers Contributors
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"context"
	"fmt"
	"net"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Checker struct {
	Clientset        kubernetes.Interface
	RuntimeclassName string
	SocketPath       string
}

func (c *Checker) GetNodeName() string {
	return os.Getenv("NODE_NAME")
}

func (c *Checker) GetAllPods(selector string) (result *corev1.PodList, err error) {
	return c.Clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: selector,
	})
}

func (c *Checker) GetAllPeerPods() (ready bool, err error) {
	nodeName := c.GetNodeName()
	logger.Printf("nodeName: %s", nodeName)

	selector := fmt.Sprintf("spec.nodeName=%s", nodeName)
	pods, err := c.GetAllPods(selector)
	if err != nil {
		return false, err
	}
	logger.Printf("Selected pods count: %d", len(pods.Items))

	for _, pod := range pods.Items {
		if pod.Spec.RuntimeClassName != nil && *pod.Spec.RuntimeClassName == c.RuntimeclassName {
			// peer-pods
			logger.Printf("Dealing with PeerPod: %s, in phase: %s", pod.ObjectMeta.Name, pod.Status.Phase)
			if pod.Status.Phase != corev1.PodRunning {
				return false, fmt.Errorf("PeerPod %s is in %s phase.", pod.ObjectMeta.Name, pod.Status.Phase)
			}
		} else {
			// standard pods
			logger.Printf("Ignored standard pod: %s", pod.ObjectMeta.Name)
		}
	}

	return true, nil
}

func (c *Checker) IsSocketOpen() (open bool, err error) {
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return true, nil
}

func CreateClientset() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func GetRuntimeclassName() string {
	runtimeclassName := os.Getenv("RUNTIMECLASS_NAME")
	if runtimeclassName != "" {
		return runtimeclassName
	}
	return DEFAULT_CC_RUNTIMECLASS_NAME
}
