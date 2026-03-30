import subprocess


with open("./setup_files/CNI.txt") as file:
    for line in file.readlines():
        match line.strip():
            case "Antrea":
                print("Antrea is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["helm", "install", "antrea", "antrea/antrea", "--version", "2.6.0", "--namespace", "kube-system"])
                subprocess.run(["minikube", "delete"])
            case "Calico":
                print("Calico is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["helm", "install", "calico", "projectcalico/tigera-operator", "--version", "v3.31.4", "--namespace", "tigera-operator", "--create-namespace"])
                subprocess.run(["minikube", "delete"])
            case "Canal":
                print("Canal is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["kubectl","apply","-f","https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/canal.yaml"])
                subprocess.run(["minikube", "delete"])
            case "Cilium":
                print("Cilium is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["helm", "install", "cilium", "cilium/cilium", "--version", "1.19.2", "--namespace", "kube-system"])
                subprocess.run(["minikube", "delete"])
            case "Kube-OVN":
                print("Kube-OVN is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["./setup_files/kube-ovn/install.sh"])
                subprocess.run(["minikube", "delete"])
            case "Kube-Router":
                print("Kube-Router is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["kubectl", "apply", "-f", "https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kube-router-all-service-daemonset.yaml"])
                subprocess.run(["minikube", "delete"])