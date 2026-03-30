
"""
--- Antrea
minikube start --network-plugin=cni --cni=false
helm repo add antrea https://charts.antrea.io
helm repo update
helm install antrea antrea/antrea --version 2.6.0 --namespace kube-system

--- Calico
minikube start --network-plugin=cni --cni=false
helm repo add projectcalico https://docs.tigera.io/calico/charts
helm repo update
helm install calico projectcalico/tigera-operator --version v3.31.4 --namespace tigera-operator --create-namespace

--- Canal
minikube start --network-plugin=cni --cni=false
helm repo add projectcalico https://docs.tigera.io/calico/charts
helm repo update
helm install canal projectcalico/tigera-operator --namespace tigera-operator --create-namespace --set installation.cniType=Canal

--- Cilium
minikube start --network-plugin=cni --cni=false
helm repo add cilium https://helm.cilium.io/
helm repo update
helm install cilium cilium/cilium --version 1.19.2 --namespace kube-system 

--- Kube-ovn
minikube start --network-plugin=cni --cni=false
./setup_files/kube-ovn/install.sh

--- Kube-router
minikube start --cni=false --extra-config=kubeadm.pod-network-cidr=10.244.0.0/16
kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kube-router-all-features.yaml
"""