/*
Copyright 2021 The Kubernetes Authors.

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

package v1beta3

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	bootstraptokenv1 "github.com/tengqm/kubeconfig/config/kubeadm/bootstraptoken/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InitConfiguration contains a list of elements that is specific "kubeadm init"-only runtime
// information.
type InitConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// `kubeadm init`-only information. These fields are solely used the first time `kubeadm init` runs.
	// After that, the information in the fields IS NOT uploaded to the `kubeadm-config` ConfigMap
	// that is used by `kubeadm upgrade` for instance. These fields must be omitempty.

	// `bootstrapTokens` is respected at `kubeadm init` time and describes a set of Bootstrap Tokens to create.
	// This information IS NOT uploaded to the kubeadm cluster configmap, partly because of its sensitive nature.
	// +optional
	BootstrapTokens []BootstrapToken `json:"bootstrapTokens,omitempty"`

	// `nodeRegistration` holds fields that relate to registering the new control-plane node to the cluster
	// +optional
	NodeRegistration NodeRegistrationOptions `json:"nodeRegistration,omitempty"`

	// `localAPIEndpoint` represents the endpoint of the API server instance that's deployed on this control plane node
	// In HA setups, this differs from ClusterConfiguration.ControlPlaneEndpoint in the sense that ControlPlaneEndpoint
	// is the global endpoint for the cluster, which then loadbalances the requests to each individual API server. This
	// configuration object lets you customize what IP/DNS name and port the local API server advertises it's accessible
	// on. By default, kubeadm tries to auto-detect the IP of the default interface and use that, but in case that process
	// fails you may set the desired value here.
	// +optional
	LocalAPIEndpoint APIEndpoint `json:"localAPIEndpoint,omitempty"`

	// `certificateKey` sets the key with which certificates and keys are encrypted prior to being uploaded in
	// a Secret in the cluster during the "uploadcerts" init phase.
	// +optional
	CertificateKey string `json:"certificateKey,omitempty"`

	// `skipPhases` is a list of phases to skip during command execution.
	// The list of phases can be obtained with the `kubeadm init --help` command.
	// The flag `--skip-phases` takes precedence over this field.
	// +optional
	SkipPhases []string `json:"skipPhases,omitempty"`

	// `patches` contains options related to applying patches to components deployed by kubeadm during
	// "kubeadm init".
	// +optional
	Patches *Patches `json:"patches,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterConfiguration contains cluster-wide configuration for a kubeadm cluster
type ClusterConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// `etcd` holds configuration for etcd.
	// +optional
	Etcd Etcd `json:"etcd,omitempty"`

	// `networking` holds configuration for the networking topology of the cluster.
	// +optional
	Networking Networking `json:"networking,omitempty"`

	// `kubernetesVersion` is the target version of the control plane.
	// +optional
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`

	// `controlPlaneEndpoint` sets a stable IP address or DNS name for the control plane; it
	// can be a valid IP address or a RFC-1123 DNS subdomain, both with optional TCP port.
	// In case the `controlPlaneEndpoint` is not specified, the `advertiseAddress` + `bindPort`
	// are used; in case the `controlPlaneEndpoint` is specified but without a TCP port,
	// the `bindPort` of the `localAPIEndpoint` is used.
	// Possible usages are:
	//
	// - In a cluster with more than one control plane instances, this field should be
	//   assigned the address of the external load balancer in front of the
	//   control plane instances.
	// - In environments with enforced node recycling, the ControlPlaneEndpoint
	//   could be used for assigning a stable DNS to the control plane.
	// +optional
	ControlPlaneEndpoint string `json:"controlPlaneEndpoint,omitempty"`

	// `apiServer` contains extra settings for the API server.
	// +optional
	APIServer APIServer `json:"apiServer,omitempty"`

	// `controllerManager` contains extra settings for the controller manager.
	// +optional
	ControllerManager ControlPlaneComponent `json:"controllerManager,omitempty"`

	// `scheduler` contains extra settings for the scheduler.
	// +optional
	Scheduler ControlPlaneComponent `json:"scheduler,omitempty"`

	// `dns` defines the options for the DNS add-on.
	// +optional
	DNS DNS `json:"dns,omitempty"`

	// `certificatesDir` specifies where to store or look for all required certificates.
	// +optional
	CertificatesDir string `json:"certificatesDir,omitempty"`

	// `imageRepository` sets the container registry to pull images from.
	// If empty, `k8s.gcr.io` will be used by default; in case of kubernetes version is
	// a CI build (kubernetes version starts with `ci/` or `ci-cross/`)
	// `gcr.io/k8s-staging-ci-images` will be used as a default for control plane
	// components and for kube-proxy, while `k8s.gcr.io` will be used for all the other images.
	// +optional
	ImageRepository string `json:"imageRepository,omitempty"`

	// Feature gates enabled by the user.
	// +optional
	FeatureGates map[string]bool `json:"featureGates,omitempty"`

	// The cluster name.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
}

// ControlPlaneComponent holds settings common to control plane component of the cluster
type ControlPlaneComponent struct {
	// `extraArgs` is an extra set of flags to pass to the control plane component.
	// A key in this map is the flag name as it appears on the
	// command line except without leading dash(es).
	// +optional
	ExtraArgs map[string]string `json:"extraArgs,omitempty"`

	// `extraVolumes` is an extra set of host volumes, mounted to the control plane component.
	// +optional
	ExtraVolumes []HostPathMount `json:"extraVolumes,omitempty"`
}

// APIServer holds settings necessary for API server deployments in the cluster
type APIServer struct {
	ControlPlaneComponent `json:",inline"`

	// `certSANs` sets extra Subject Alternative Names for the API Server signing cert.
	// +optional
	CertSANs []string `json:"certSANs,omitempty"`

	// `timeoutForControlPlane` controls the timeout that we use for API server to appear
	// +optional
	TimeoutForControlPlane *metav1.Duration `json:"timeoutForControlPlane,omitempty"`
}

// DNSAddOnType defines string identifying DNS add-on types
type DNSAddOnType string

// DNS defines the DNS addon that should be used in the cluster
type DNS struct {
	// `imageMeta` allows to customize the image used for the DNS component.
	ImageMeta `json:",inline"`
}

// ImageMeta allows to customize the image used for components that are not
// originated from the Kubernetes/Kubernetes release process
type ImageMeta struct {
	// `imageRepository` sets the container registry to pull images from.
	// If not set, the ImageRepository defined in ClusterConfiguration will be used instead.
	// +optional
	ImageRepository string `json:"imageRepository,omitempty"`

	// `imageTag` allows to specify a tag for the image.
	// In case this value is set, kubeadm does not change automatically the
	// version of the above components during upgrades.
	// +optional
	ImageTag string `json:"imageTag,omitempty"`
}

// APIEndpoint struct contains elements of API server instance deployed on a node.
type APIEndpoint struct {
	// `advertiseAddress` sets the IP address for the API server to advertise.
	// +optional
	AdvertiseAddress string `json:"advertiseAddress,omitempty"`

	// `bindPort` sets the secure port for the API Server to bind to. Defaults to 6443.
	// +optional
	BindPort int32 `json:"bindPort,omitempty"`
}

// NodeRegistrationOptions holds fields that relate to registering a new control-plane or node to the cluster, either via "kubeadm init" or "kubeadm join"
type NodeRegistrationOptions struct {

	// `name` is the `.metadata.name` field of the Node API object that will be created in this
	// `kubeadm init` or `kubeadm join` operation.
	// This field is also used in the `CommonName` field of the kubelet's client certificate to the
	// API server. Defaults to the hostname of the node if not provided.
	// +optional
	Name string `json:"name,omitempty"`

	// `criSocket` is used to retrieve container runtime info. This information will be
	// annotated to the Node API object, for later re-use.
	// +optional
	CRISocket string `json:"criSocket,omitempty"`

	// `taints` specifies the taints the Node API object should be registered with. If
	// this field is unset, i.e. nil, in the `kubeadm init` process, it will be defaulted
	// to `['"node-role.kubernetes.io/master"=""']`. If you don't want to taint your
	// control-plane node, set this field to an empty list, i.e. `taints: []` in the YAML
	// file. This field is solely used for Node registration.
	Taints []corev1.Taint `json:"taints"`

	// `kubeletExtraArgs` passes through extra arguments to the kubelet. The arguments here
	// are passed to the kubelet command line via the environment file kubeadm writes at
	// runtime for the kubelet to source. This overrides the generic base-level
	// configuration in the "kubelet-config-1.X" ConfigMap. Flags have higher priority when
	// parsing. These values are local and specific to the node kubeadm is executing on.
	// A key in this map is the flag name as it appears on the command line except without
	// leading dash(es).
	// +optional
	KubeletExtraArgs map[string]string `json:"kubeletExtraArgs,omitempty"`

	// `ignorePreflightErrors` provides a slice of pre-flight errors to be ignored when
	// the current node is registered.
	// +optional
	IgnorePreflightErrors []string `json:"ignorePreflightErrors,omitempty"`

	// `imagePullPolicy` specifies the policy for image pulling during `kubeadm init` and
	// `kubeadm join` operations.
	// The value of this field must be one of "Always", "IfNotPresent" or "Never".
	// If this field is unset kubeadm will default it to "IfNotPresent", or pull the required
	// images if not present on the host.
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
}

// Networking contains elements describing cluster's networking configuration
type Networking struct {
	// `serviceSubnet` is the subnet used by k8s services. Defaults to "10.96.0.0/12".
	// +optional
	ServiceSubnet string `json:"serviceSubnet,omitempty"`
	// `podSubnet` is the subnet used by Pods.
	// +optional
	PodSubnet string `json:"podSubnet,omitempty"`
	// `dnsDomain` is the DNS domain used by k8s services. Defaults to "cluster.local".
	// +optional
	DNSDomain string `json:"dnsDomain,omitempty"`
}

// Etcd contains elements describing Etcd configuration.
type Etcd struct {
	// `local` provides configuration knobs for configuring the local etcd instance.
	// `local` and `external` are mutually exclusive.
	// +optional
	Local *LocalEtcd `json:"local,omitempty"`

	// `external` describes how to connect to an external etcd cluster.
	// `local` and `external` are mutually exclusive.
	// +optional
	External *ExternalEtcd `json:"external,omitempty"`
}

// LocalEtcd describes that kubeadm should run an etcd cluster locally
type LocalEtcd struct {
	// `ImageMeta` allows to customize the container used for etcd.
	ImageMeta `json:",inline"`

	// `dataDir` is the directory etcd will place its data.
	// Defaults to "/var/lib/etcd".
	DataDir string `json:"dataDir"`

	// `extraArgs` are extra arguments provided to the etcd binary
	// when run inside a static pod.
	// A key in this map is the flag name as it appears on the command line except
	// without leading dash(es).
	// +optional
	ExtraArgs map[string]string `json:"extraArgs,omitempty"`

	// `serverCertSANs` sets extra Subject Alternative Names for the etcd server signing cert.
	// +optional
	ServerCertSANs []string `json:"serverCertSANs,omitempty"`
	// `peerCertSANs` sets extra Subject Alternative Names for the etcd peer signing cert.
	// +optional
	PeerCertSANs []string `json:"peerCertSANs,omitempty"`
}

// ExternalEtcd describes an external etcd cluster.
// Kubeadm has no knowledge of where certificate files live and they must be supplied.
type ExternalEtcd struct {
	// `endpoints` are endpoints of etcd members. This field is required.
	Endpoints []string `json:"endpoints"`

	// `caFile` is an SSL Certificate Authority file used to secure etcd communication.
	// Required if using a TLS connection.
	CAFile string `json:"caFile"`

	// `certFile` is an SSL certification file used to secure etcd communication.
	// Required if using a TLS connection.
	CertFile string `json:"certFile"`

	// `keyFile` is an SSL key file used to secure etcd communication.
	// Required if using a TLS connection.
	KeyFile string `json:"keyFile"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// JoinConfiguration contains elements describing a particular node.
type JoinConfiguration struct {
	metav1.TypeMeta `json:",inline"`

	// `nodeRegistration` holds fields that relate to registering the new control-plane
	// node to the cluster
	// +optional
	NodeRegistration NodeRegistrationOptions `json:"nodeRegistration,omitempty"`

	// `caCertPath` is the path to the SSL certificate authority used to
	// secure comunications between node and control-plane.
	// Defaults to "/etc/kubernetes/pki/ca.crt".
	// +optional
	CACertPath string `json:"caCertPath,omitempty"`

	// `discovery` specifies the options for the kubelet to use during the TLS Bootstrap process.
	Discovery Discovery `json:"discovery"`

	// `controlPlane` defines the additional control plane instance to be deployed on the
	// joining node. If nil, no additional control plane instance will be deployed.
	// +optional
	ControlPlane *JoinControlPlane `json:"controlPlane,omitempty"`

	// `skipPhases` is a list of phases to skip during command execution.
	// The list of phases can be obtained with the `kubeadm join --help` command.
	// The flag `--skip-phases` takes precedence over this field.
	// +optional
	SkipPhases []string `json:"skipPhases,omitempty"`

	// `patches` contains options related to applying patches to components deployed by kubeadm during
	// `kubeadm join`.
	// +optional
	Patches *Patches `json:"patches,omitempty"`
}

// JoinControlPlane contains elements describing an additional control plane instance to be deployed on the joining node.
type JoinControlPlane struct {
	// `localAPIEndpoint` represents the endpoint of the API server instance to be deployed
	// on this node.
	// +optional
	LocalAPIEndpoint APIEndpoint `json:"localAPIEndpoint,omitempty"`

	// `certificateKey` is the key that is used for decryption of certificates after they
	// are downloaded from the secret upon joining a new control plane node. The
	// corresponding encryption key is in the InitConfiguration.
	// +optional
	CertificateKey string `json:"certificateKey,omitempty"`
}

// Discovery specifies the options for the kubelet to use during the TLS Bootstrap process
type Discovery struct {
	// `bootstrapToken` is used to set the options for bootstrap token based discovery.
	// `bootstrapToken` and `file` are mutually exclusive.
	// +optional
	BootstrapToken *BootstrapTokenDiscovery `json:"bootstrapToken,omitempty"`

	// `file` specifies a file or URL to a kubeconfig file from which to load cluster information.
	// `bootstrapToken` and `file` are mutually exclusive.
	// +optional
	File *FileDiscovery `json:"file,omitempty"`

	// `tlsBootstrapToken` is a token used for TLS bootstrapping.
	// If `bootstrapToken` is set, this field is defaulted to `bootstrapToken.token`,
	// but can be overridden.
	// If `file` is set, this field **must be set** in case the KubeConfigFile does
	// not contain any other authentication information
	// +optional
	TLSBootstrapToken string `json:"tlsBootstrapToken,omitempty" datapolicy:"token"`

	// `timeout` modifies the discovery timeout.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
}

// BootstrapTokenDiscovery is used to set the options for bootstrap token based discovery
type BootstrapTokenDiscovery struct {
	// `token` is a token used to validate cluster information fetched from the control-plane.
	Token string `json:"token"`

	// `apiServerEndpoint` is an IP or domain name to the API server from which
	// information will be fetched.
	// +optional
	APIServerEndpoint string `json:"apiServerEndpoint,omitempty"`

	// CACertHashes specifies a set of public key pins to verify when token-based
	// discovery is used. The root CA found during discovery must match one of these
	// values. Specifying an empty set disables root CA pinning, which can be unsafe.
	// Each hash is specified as `<type>:<value>`, where the only currently supported
	// type is "sha256". This is a hex-encoded SHA-256 hash of the Subject Public Key
	// Info (SPKI) object in DER-encoded ASN.1. These hashes can be calculated using,
	// for example, OpenSSL.
	// +optional
	CACertHashes []string `json:"caCertHashes,omitempty" datapolicy:"security-key"`

	// `unsafeSkipCAVerification` allows token-based discovery without CA verification
	// via `caCertHashes`. This can weaken the security of kubeadm since other nodes
	// can impersonate the control-plane.
	// +optional
	UnsafeSkipCAVerification bool `json:"unsafeSkipCAVerification,omitempty"`
}

// FileDiscovery is used to specify a file or URL to a kubeconfig file from which to load cluster information
type FileDiscovery struct {
	// `kubeConfigPath` specifies the actual file path or URL to the kubeconfig file
	// from which to load cluster information
	KubeConfigPath string `json:"kubeConfigPath"`
}

// HostPathMount contains elements describing volumes that are mounted from the host.
type HostPathMount struct {
	// `name` is the volume name inside the Pod template.
	Name string `json:"name"`
	// `hostPath` is the path in the host that will be mounted inside the Pod.
	HostPath string `json:"hostPath"`
	// `mountPath` is the path inside the Pod where the `hostPath` volume is mounted.
	MountPath string `json:"mountPath"`
	// `readOnly` controls write access to the volume.
	// +optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// `pathType` is the type of the `hostPath` volume.
	// +optional
	PathType corev1.HostPathType `json:"pathType,omitempty"`
}

// Patches contains options related to applying patches to components deployed by kubeadm.
type Patches struct {
	// `directory` is a path to a directory that contains files named
	// `target[suffix][+patchtype].extension`.
	// For example, `kube-apiserver0+merge.yaml` or just `etcd.json`. `target` can be one of
	// "kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd". `patchtype` can be one
	// of "strategic", "merge" or "json" and they match the patch formats supported by kubectl.
	// The default `patchtype` is "strategic". `extension` must be either "json" or "yaml".
	// `suffix` is an optional string that can be used to determine which patches are applied
	// first alpha-numerically.
	// +optional
	Directory string `json:"directory,omitempty"`
}
