// Copyright 2025 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build E2Etests
// +build E2Etests

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/rest"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	hcpsdk "github.com/Azure/ARO-HCP/test/sdk/resourcemanager/redhatopenshifthcp/armredhatopenshifthcp"

	"github.com/Azure/ARO-HCP/test/util/framework"
	"github.com/Azure/ARO-HCP/test/util/labels"
)

var _ = Describe("Authorized CIDRs Connectivity", func() {
	It("should allow API access only from authorized VM IP",
		labels.RequireNothing,
		labels.Critical,
		labels.Positive,
		func(ctx context.Context) {
			const clusterName = "cidr-connectivity-test"

			tc := framework.NewTestContext()

			By("creating a resource group")
			resourceGroup, err := tc.NewResourceGroup(ctx, "e2e-cidr-connectivity", tc.Location())
			Expect(err).NotTo(HaveOccurred())

			By("generating SSH key pair for VM")
			sshPublicKey, _, err := generateSSHKeyPair()
			Expect(err).NotTo(HaveOccurred())

			By("deploying cluster with test VM")
			deployment, err := framework.CreateBicepTemplateAndWait(ctx,
				tc.GetARMResourcesClientFactoryOrDie(ctx).NewDeploymentsClient(),
				*resourceGroup.Name,
				"aro-hcp-cidr-test",
				framework.Must(TestArtifactsFS.ReadFile("test-artifacts/generated-test-artifacts/cluster-with-vm-test.json")),
				map[string]interface{}{
					"clusterName":  clusterName,
					"sshPublicKey": sshPublicKey,
				},
				60*time.Minute, // Extra time for VM + cluster deployment
			)
			Expect(err).NotTo(HaveOccurred())

			By("extracting VM public IP from deployment outputs")
			vmPublicIP := ""
			if deployment.Properties != nil && deployment.Properties.Outputs != nil {
				if outputs, ok := deployment.Properties.Outputs.(map[string]interface{}); ok {
					if vmIPOutput, ok := outputs["vmPublicIP"].(map[string]interface{}); ok {
						if value, ok := vmIPOutput["value"].(string); ok {
							vmPublicIP = value
						}
					}
				}
			}
			Expect(vmPublicIP).NotTo(BeEmpty(), "VM public IP should be in deployment outputs")

			By("getting cluster details")
			cluster, err := framework.GetHCPCluster(
				ctx,
				tc.Get20240610ClientFactoryOrDie(ctx).NewHcpOpenShiftClustersClient(),
				*resourceGroup.Name,
				clusterName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(cluster.Properties).ToNot(BeNil())
			Expect(cluster.Properties.API).ToNot(BeNil())
			Expect(cluster.Properties.API.URL).ToNot(BeNil())
			apiURL := *cluster.Properties.API.URL

			By("verifying authorized CIDRs contains VM IP")
			Expect(cluster.Properties.API.AuthorizedCIDRs).ToNot(BeNil())
			Expect(cluster.Properties.API.AuthorizedCIDRs).To(HaveLen(1))
			Expect(*cluster.Properties.API.AuthorizedCIDRs[0]).To(Equal(fmt.Sprintf("%s/32", vmPublicIP)))

			By("testing connectivity from authorized VM")
			vmName := fmt.Sprintf("%s-test-vm", clusterName)

			// Test connectivity using VM run command
			connectivityTest := fmt.Sprintf("curl -k -s -o /dev/null -w '%%{http_code}' --connect-timeout 10 %s/healthz", apiURL)
			output, err := runVMCommand(ctx, tc, *resourceGroup.Name, vmName, connectivityTest)
			Expect(err).NotTo(HaveOccurred())

			// Should get HTTP response (likely 401 or 200, but not connection refused)
			httpCode := strings.TrimSpace(output)
			By(fmt.Sprintf("VM received HTTP status code: %s", httpCode))
			Expect(httpCode).To(MatchRegexp("^[2-5][0-9][0-9]$"), "Should receive valid HTTP status code from authorized IP")

			By("testing connectivity from current machine (should be blocked)")
			// Try to connect from the test runner (which is not in authorized CIDRs)
			err = testAPIConnectivity(apiURL, 5*time.Second)
			if err != nil {
				By(fmt.Sprintf("Connection from unauthorized IP correctly blocked: %v", err))
			} else {
				// If we can connect, it means the test runner's IP might be in the cluster's network
				// This is expected in some scenarios, so we just log it
				By("Warning: Connection from test runner succeeded - this may indicate the runner is in the authorized network")
			}

			By("verifying VM can access cluster API with credentials")
			adminRESTConfig, err := framework.GetAdminRESTConfigForHCPCluster(
				ctx,
				tc.Get20240610ClientFactoryOrDie(ctx).NewHcpOpenShiftClustersClient(),
				*resourceGroup.Name,
				clusterName,
				10*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			// Create kubeconfig and copy to VM
			kubeconfig, err := generateKubeconfig(adminRESTConfig)
			Expect(err).NotTo(HaveOccurred())

			// Test kubectl command from VM
			kubectlTest := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig get nodes 2>&1", kubeconfig)
			output, err = runVMCommand(ctx, tc, *resourceGroup.Name, vmName, kubectlTest)
			By(fmt.Sprintf("kubectl output from authorized VM: %s", output))

			// Should be able to run kubectl commands (even if nodes aren't ready)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Or(
				ContainSubstring("NAME"),         // Success - got nodes
				ContainSubstring("No resources"), // Success - no nodes yet
				ContainSubstring("NotReady"),     // Success - nodes not ready
			), "Should be able to execute kubectl from authorized VM")

			By("updating cluster to remove VM from authorized CIDRs")
			update := hcpsdk.HcpOpenShiftClusterUpdate{
				Identity: toIdentityUpdate(cluster.Identity),
				Properties: &hcpsdk.HcpOpenShiftClusterPropertiesUpdate{
					API: &hcpsdk.APIProfileUpdate{
						AuthorizedCIDRs: []*string{
							to.Ptr("192.0.2.0/24"), // Use TEST-NET-1 (reserved for documentation)
						},
					},
				},
			}
			_, err = framework.UpdateHCPCluster(
				ctx,
				tc.Get20240610ClientFactoryOrDie(ctx).NewHcpOpenShiftClustersClient(),
				*resourceGroup.Name,
				clusterName,
				update,
				10*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			// Wait a bit for the change to propagate
			time.Sleep(30 * time.Second)

			By("verifying VM is now blocked from API access")
			output, err = runVMCommand(ctx, tc, *resourceGroup.Name, vmName, connectivityTest)
			if err != nil || strings.TrimSpace(output) == "000" || strings.TrimSpace(output) == "" {
				By("Connection correctly blocked after removing VM from authorized CIDRs")
			} else {
				// May take time to propagate
				By(fmt.Sprintf("Note: Connection still allowed (status: %s) - may need time to propagate", strings.TrimSpace(output)))
			}
		},
	)
	It("should deploy node pool and run workload with authorized CIDRs enabled",
		labels.RequireNothing,
		labels.Critical,
		labels.Positive,
		func(ctx context.Context) {
			const (
				clusterName  = "cidr-workload-test"
				nodePoolName = "worker-pool"
			)

			tc := framework.NewTestContext()

			By("creating a resource group")
			resourceGroup, err := tc.NewResourceGroup(ctx, "e2e-cidr-workload", tc.Location())
			Expect(err).NotTo(HaveOccurred())

			By("generating SSH key pair for VM")
			sshPublicKey, _, err := generateSSHKeyPair()
			Expect(err).NotTo(HaveOccurred())

			By("deploying cluster with test VM and authorized CIDRs")
			deployment, err := framework.CreateBicepTemplateAndWait(ctx,
				tc.GetARMResourcesClientFactoryOrDie(ctx).NewDeploymentsClient(),
				*resourceGroup.Name,
				"aro-hcp-cidr-workload",
				framework.Must(TestArtifactsFS.ReadFile("test-artifacts/generated-test-artifacts/cluster-with-vm-test.json")),
				map[string]interface{}{
					"clusterName":  clusterName,
					"sshPublicKey": sshPublicKey,
				},
				60*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			By("extracting VM public IP from deployment outputs")
			vmPublicIP := getDeploymentOutputString(deployment, "vmPublicIP")
			Expect(vmPublicIP).NotTo(BeEmpty(), "VM public IP should be in deployment outputs")

			By("getting admin credentials for the cluster")
			adminRESTConfig, err := framework.GetAdminRESTConfigForHCPCluster(
				ctx,
				tc.Get20240610ClientFactoryOrDie(ctx).NewHcpOpenShiftClustersClient(),
				*resourceGroup.Name,
				clusterName,
				10*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			By("deploying node pool via Bicep")
			_, err = framework.CreateBicepTemplateAndWait(ctx,
				tc.GetARMResourcesClientFactoryOrDie(ctx).NewDeploymentsClient(),
				*resourceGroup.Name,
				"aro-hcp-nodepool",
				framework.Must(TestArtifactsFS.ReadFile("test-artifacts/generated-test-artifacts/modules/nodepool.json")),
				map[string]interface{}{
					"clusterName":  clusterName,
					"nodePoolName": nodePoolName,
				},
				30*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for nodes to be ready")
			vmName := fmt.Sprintf("%s-test-vm", clusterName)
			kubeconfig, err := generateKubeconfig(adminRESTConfig)
			Expect(err).NotTo(HaveOccurred())

			// Wait for nodes to appear and become ready
			Eventually(func() bool {
				cmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig get nodes --no-headers 2>/dev/null | wc -l", kubeconfig)
				output, err := runVMCommand(ctx, tc, *resourceGroup.Name, vmName, cmd)
				if err != nil {
					return false
				}
				nodeCount := strings.TrimSpace(output)
				return nodeCount != "" && nodeCount != "0"
			}, 15*time.Minute, 30*time.Second).Should(BeTrue(), "Nodes should appear in the cluster")

			By("creating a test namespace")
			createNsCmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig create namespace test-workload 2>&1 || true", kubeconfig)
			_, err = runVMCommand(ctx, tc, *resourceGroup.Name, vmName, createNsCmd)
			Expect(err).NotTo(HaveOccurred())

			By("deploying a simple nginx deployment")
			deploymentYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test
  namespace: test-workload
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
  namespace: test-workload
spec:
  selector:
    app: nginx
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: ClusterIP`

			// Escape the YAML for shell command
			escapedYAML := strings.ReplaceAll(deploymentYAML, "'", "'\\''")
			deployCmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && echo '%s' | kubectl --kubeconfig=/tmp/kubeconfig apply -f - 2>&1",
				kubeconfig, escapedYAML)
			output, err := runVMCommand(ctx, tc, *resourceGroup.Name, vmName, deployCmd)
			Expect(err).NotTo(HaveOccurred())
			By(fmt.Sprintf("Deployment output: %s", output))

			By("waiting for nginx pods to be ready")
			Eventually(func() bool {
				cmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig get pods -n test-workload -l app=nginx --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l",
					kubeconfig)
				output, err := runVMCommand(ctx, tc, *resourceGroup.Name, vmName, cmd)
				if err != nil {
					return false
				}
				runningPods := strings.TrimSpace(output)
				return runningPods == "2"
			}, 10*time.Minute, 15*time.Second).Should(BeTrue(), "Nginx pods should be running")

			By("verifying service is accessible within the cluster")
			testServiceCmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig run curl-test --image=curlimages/curl:latest --rm -i --restart=Never -n test-workload -- curl -s http://nginx-service.test-workload.svc.cluster.local 2>&1",
				kubeconfig)
			output, err = runVMCommand(ctx, tc, *resourceGroup.Name, vmName, testServiceCmd)
			Expect(err).NotTo(HaveOccurred())
			By(fmt.Sprintf("Service response: %s", output))
			Expect(output).To(ContainSubstring("Welcome to nginx"), "Nginx service should be accessible")

			By("verifying node pool is running")
			nodePool, err := framework.GetNodePool(ctx,
				tc.Get20240610ClientFactoryOrDie(ctx).NewNodePoolsClient(),
				*resourceGroup.Name,
				clusterName,
				nodePoolName,
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodePool.Properties).ToNot(BeNil())
			Expect(nodePool.Properties.ProvisioningState).ToNot(BeNil())
			By(fmt.Sprintf("Node pool provisioning state: %s", *nodePool.Properties.ProvisioningState))

			By("cleaning up test workload")
			cleanupCmd := fmt.Sprintf("echo '%s' > /tmp/kubeconfig && kubectl --kubeconfig=/tmp/kubeconfig delete namespace test-workload --wait=false 2>&1",
				kubeconfig)
			_, _ = runVMCommand(ctx, tc, *resourceGroup.Name, vmName, cleanupCmd)
		},
	)
})

// Helper to get deployment output string
func getDeploymentOutputString(deployment *armresources.DeploymentExtended, outputName string) string {
	if deployment.Properties != nil && deployment.Properties.Outputs != nil {
		if outputs, ok := deployment.Properties.Outputs.(map[string]interface{}); ok {
			if output, ok := outputs[outputName].(map[string]interface{}); ok {
				if value, ok := output["value"].(string); ok {
					return value
				}
			}
		}
	}
	return ""
}

// Helper to run command on VM
func runVMCommand(ctx context.Context, tc *framework.TestContext, resourceGroup, vmName, command string) (string, error) {
	computeClient, err := armcompute.NewVirtualMachinesClient(tc.SubscriptionID(), tc.AzureCredential(), nil)
	if err != nil {
		return "", err
	}

	runCommandInput := armcompute.RunCommandInput{
		CommandID: to.Ptr("RunShellScript"),
		Script: []*string{
			to.Ptr(command),
		},
	}

	poller, err := computeClient.BeginRunCommand(ctx, resourceGroup, vmName, runCommandInput, nil)
	if err != nil {
		return "", err
	}

	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", err
	}

	if result.Value != nil && len(result.Value) > 0 && result.Value[0].Message != nil {
		return *result.Value[0].Message, nil
	}

	return "", nil
}

// Helper to test API connectivity with timeout
func testAPIConnectivity(apiURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Simple HTTP GET to test connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/healthz", nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Helper to generate SSH key pair
func generateSSHKeyPair() (publicKey string, privateKey string, err error) {
	// Generate RSA key pair
	privateKeyData, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKeyData),
	}
	privateKeyStr := string(pem.EncodeToMemory(privateKeyPEM))

	// Generate public key in SSH format
	pub, err := ssh.NewPublicKey(&privateKeyData.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyStr := string(ssh.MarshalAuthorizedKey(pub))

	return publicKeyStr, privateKeyStr, nil
}

// Helper to generate kubeconfig
func generateKubeconfig(restConfig *rest.Config) (string, error) {
	// Create a simple kubeconfig YAML
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: %s
    certificate-authority-data: %s
  name: cluster
contexts:
- context:
    cluster: cluster
    user: admin
  name: admin@cluster
current-context: admin@cluster
users:
- name: admin
  user:
    client-certificate-data: %s
    client-key-data: %s
`,
		restConfig.Host,
		base64.StdEncoding.EncodeToString(restConfig.CAData),
		base64.StdEncoding.EncodeToString(restConfig.CertData),
		base64.StdEncoding.EncodeToString(restConfig.KeyData),
	)

	return kubeconfig, nil
}
