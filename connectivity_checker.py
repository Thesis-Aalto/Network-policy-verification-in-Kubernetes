import subprocess

class ConnectivityChecker():
    def __init__(self, policy_path, testbed_path, workloads):
        self.policy_path = policy_path
        self.workloads = workloads
        self.all_destinations = []
    def get_pod_ips_by_label(self, namespace="default"):
        for name, value in self.workloads.items():
            label_selector = ""
            for key, value in value["pod_labels"].items():
                label_selector+=key+"="+value+","
            label_selector = label_selector[:-1]
            result = subprocess.run(
                ["kubectl", "get", "pods", "-l", label_selector, "-o", "jsonpath={.items[0].status.podIP}"],
                capture_output=True,
                text=True
            )
            pod_ip = result.stdout.strip()
            self.workloads[name]["pod_ip"] = pod_ip
            print(self.workloads[name])
    






