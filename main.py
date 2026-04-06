import subprocess
import time


def api_kind_exists(group_version: str, kind: str) -> bool:
    p = subprocess.run(
        ["kubectl", "api-resources", "--api-group", group_version.split("/")[0], "-o", "name"],
        capture_output=True,
        text=True,
    )
    return p.returncode == 0 and kind.lower() in p.stdout.lower()
def wait_for_kinds(timeout_s=240, interval_s=2):
    deadline = time.time() + timeout_s
    needed = [("operator.tigera.io/v1", "Installation"),
              ("operator.tigera.io/v1", "APIServer"),
              ("operator.tigera.io/v1", "Goldmane"),
              ("operator.tigera.io/v1", "Whisker")]
    while time.time() < deadline:
        if all(api_kind_exists(gv, k) for gv, k in needed):
            return
        time.sleep(interval_s)
    raise RuntimeError("Timed out waiting for Tigera operator API kinds to become available")


def wait_for_pods_to_exist(namespace, selector):
    print(f"Waiting for pods with selector {selector} to appear...")
    while True:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", namespace, "-l", selector, "--no-headers"],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print("Pods found!")
            break
        time.sleep(2)

def start_aks_store():
    print("AKS Store is started")
    subprocess.run(["kubectl", "apply", "-f", "./testbeds/aks-store-demo/aks-store-all-in-one.yaml"])
    wait_for_aks_store()
    subprocess.run(["kubectl", "delete", "-f", "./testbeds/aks-store-demo/aks-store-all-in-one.yaml"])
    print("AKS Store is finished")

def start_istio_bookinfo():
    print("Istio Bookinfo is started")
    subprocess.run(["kubectl", "apply", "-f", "./testbeds/istio-bookinfo/bookinfo.yaml"])
    wait_for_istio_bookinfo()
    subprocess.run(["kubectl", "delete", "-f", "./testbeds/istio-bookinfo/bookinfo.yaml"])
    print("Istio Bookinfo is finished")

def wait_for_aks_store():
    subprocess.run(["kubectl", "rollout", "status", "deployment/order-service", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/makeline-service", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/store-front", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "statefulset/mongodb", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "statefulset/rabbitmq", "--timeout=120s"])

def wait_for_istio_bookinfo():
    subprocess.run(["kubectl", "rollout", "status", "deployment/details-v1", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/ratings-v1", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/reviews-v1", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/reviews-v2", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/reviews-v3", "--timeout=120s"])
    subprocess.run(["kubectl", "rollout", "status", "deployment/productpage-v1", "--timeout=120s"])


with open("./setup_files/CNI.txt") as file:
    
    for line in file.readlines():
        match line.strip():
            case "Antrea":
                print("Antrea is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["helm", "install", "antrea", "antrea/antrea", "--version", "2.6.0", "--namespace", "kube-system"])
                wait_for_pods_to_exist("kube-system", "app=antrea")
                subprocess.run(["kubectl", "wait", "pod", "-n", "kube-system", "-l", "app=antrea", "--for=condition=Ready", "--timeout=60s"])
                start_aks_store()
                start_istio_bookinfo()
                creator = NetworkCreatorClass(
                    inventory_yaml_path="./testbeds/aks-store-demo/aks-store-all-in-one.yaml",
                    include_deny_all=False,          # runner handles baseline deny-all now
                    include_ingress=True,
                    include_egress=True,
                    max_destinations_per_policy=2,
                )
                runner = ConnectivityPolicyRunner(
                    creator=creator,
                    cni="Calico",
                    testbed="aks-store-demo",
                    baseline_deny_all=True,
                    results_path="out/results.jsonl",
                    results_csv_path="out/results.csv",
                    probe_binary="nc",
                )
                subprocess.run(["minikube", "delete"])
                print("Antrea is finished")
                break
            case "Calico":
                print("Calico is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=calico"])
                subprocess.run(["kubectl", "apply", "-f", "https://raw.githubusercontent.com/projectcalico/calico/v3.31.4/manifests/tigera-operator.yaml"])
                wait_for_kinds()
                subprocess.run(["kubectl", "apply", "-f", "https://raw.githubusercontent.com/projectcalico/calico/v3.31.4/manifests/custom-resources.yaml"])
                subprocess.run(["kubectl", "wait", "--for=condition=Available", "deployment/tigera-operator","-n", "tigera-operator", "--timeout=60s"])
                start_aks_store()
                start_istio_bookinfo()
                subprocess.run(["minikube", "delete"])
                print("Calico is finished")
            case "Canal":
                print("Canal is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["kubectl","apply","-f","https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/canal.yaml"])
                subprocess.run(["kubectl", "wait", "pod", "-n", "kube-system", "-l", "k8s-app=canal", "--for=condition=Ready", "--timeout=60s"])
                start_aks_store()
                start_istio_bookinfo()
                subprocess.run(["minikube", "delete"])
                print("Canal is finished")
            case "Cilium":
                print("Cilium is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["helm", "install", "cilium", "cilium/cilium", "--version", "1.19.2", "--namespace", "kube-system"])
                subprocess.run(["kubectl", "rollout", "status", "ds/cilium", "-n", "kube-system", "--timeout=300s"])
                #TODO (Optional): Add control for cilium-envoy(layer 7)
                start_aks_store()
                start_istio_bookinfo()
                subprocess.run(["minikube", "delete"])
                print("Cilium is finished")
            case "Kube-Router":
                print("Kube-Router is started")
                subprocess.run(["minikube", "start", "--network-plugin=cni", "--cni=false"])
                subprocess.run(["kubectl", "apply", "-f", "https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter-all-features.yaml"])
                subprocess.run(["kubectl", "wait", "pod", "-n", "kube-system", "-l", "k8s-app=kube-router", "--for=condition=Ready", "--timeout=60s"])
                start_aks_store()
                start_istio_bookinfo()
                subprocess.run(["minikube", "delete"])
                print("Kube-Router is finished")