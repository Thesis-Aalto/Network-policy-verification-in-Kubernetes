import yaml
import itertools
import os

class NetworkCreatorClass():
    def __init__(self, yaml_path, max_subset=2, output_dir="./network_policies"):
        self.yaml_path = yaml_path
        self.max_subset = max_subset
        self.workloads = dict()
        self.services = dict()
        self.policies = []
        self.output_dir = output_dir

    def parse_kubernetes_yaml(self):
        with open(self.yaml_path, 'r') as file:
            documents = list(yaml.safe_load_all(file))
        for document in documents:
            if not document:
                continue
            if document["kind"] == "Service":
                self._parse_service(document)
            elif document["kind"] == "StatefulSet" or document["kind"] == "Deployment":
                self._parse_workload(document)
            else:
                continue
        self._link_services_to_workloads()

    def _parse_workload(self, document):
        container_ports = []
        for container in document["spec"]["template"]["spec"]["containers"]:
            for p in container.get("ports") or []:
                container_ports.append({
                    "containerPort": p.get("containerPort"),
                    "protocol": p.get("protocol") or "TCP",
                    "name": p.get("name"), 
                })

        workload = {
            "name": document["metadata"]["name"],
            "kind": document["kind"],
            "pod_labels": document["spec"]["template"]["metadata"]["labels"],
            "container_ports": container_ports,
            "service": None,  
        }
        self.workloads[document["metadata"]["name"]] = workload

    def _parse_service(self, document):
        ports = []
        for p in document["spec"]["ports"] or []:
            ports.append({
                "port": p["port"],           
                "targetPort": p.get("targetPort") or p.get("port"),
                "protocol": p.get("protocol") or "TCP",
            })
        self.services[document["metadata"]["name"]] = {
            "name": document["metadata"]["name"],
            "selector": document["spec"]["selector"],   # used to match pods
            "ports": ports,
        }
    
    def _link_services_to_workloads(self):
        for svc_name, svc in self.services.items():
            svc_selector = svc["selector"]
            if not svc_selector:
                continue
            for workload_name, workload in self.workloads.items():
                pod_labels = workload["pod_labels"]
                if self._labels_match(svc_selector, pod_labels):
                    workload["service"] = svc

    def _labels_match(self, selector: dict, labels: dict) -> bool:
        return all(
            labels.get(k) == v
            for k, v in selector.items()
        )

    def _get_policy_ports(self, workload):
        if workload.get("service"):
            return [
                {
                    "port": p["targetPort"],
                    "protocol": p["protocol"],
                }
                for p in workload["service"]["ports"]
                if p.get("targetPort")
            ]

    def generate_policies(self):
        workload_list = list(self.workloads.values())

        for source in workload_list:
            destinations = [w for w in workload_list if w["name"] != source["name"]]
            for size in range(1, self.max_subset + 1):
                for subset in itertools.combinations(destinations, size):
                    subset = list(subset)
                    self._generate_policy_pair(source, subset)

        return self.policies

    def _generate_policy_pair(self, source, dest_subset):
        source_labels = source["pod_labels"]
        egress_rules = []
        
        for dest in dest_subset:
            ports = self._get_policy_ports(dest)
            rule = {"to": [{"podSelector": {"matchLabels": dest["pod_labels"]}}]}
            
            if ports:
                rule["ports"] = [
                    {"protocol": proto, "port": p["port"]}
                    for p in ports
                    for proto in ["TCP", "UDP"]
                ]
            egress_rules.append(rule)

        egress_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": self._policy_name("egress", source, dest_subset),
            },
            "spec": {
                "podSelector": {"matchLabels": source_labels},
                "policyTypes": ["Egress"],
                "egress": egress_rules,
            },
        }
        self.policies.append(egress_policy)

        for dest in dest_subset:
            ports = self._get_policy_ports(dest)
            ingress_rule = {"from": [{"podSelector": {"matchLabels": source_labels}}]}
            
            if ports:
                # Apply the same dual-protocol logic for Ingress
                ingress_rule["ports"] = [
                    {"protocol": proto, "port": p["port"]}
                    for p in ports
                    for proto in ["TCP", "UDP"]
                ]
                
            ingress_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": self._policy_name("ingress", source, [dest]),
                },
                "spec": {
                    "podSelector": {"matchLabels": dest["pod_labels"]},
                    "policyTypes": ["Ingress"],
                    "ingress": [ingress_rule],
                },
            }
            self.policies.append(ingress_policy)

    def _policy_name(self, direction, source, dest_subset):
        dest_names = "-".join(d["name"] for d in dest_subset)
        name = f"{direction}-{source['name']}-to-{dest_names}"
        return name[:63]
    
    def save_policies(self):
        if not self.policies:
            raise RuntimeError("No policies to save. Run generate_policies() first.")

        saved = []
        for policy in self.policies:
            pod_selector = policy["spec"].get("podSelector", {}).get("matchLabels", {})
            if pod_selector:
                pod_folder_name = "_".join([f"{v}" for k, v in pod_selector.items()])
            else:
                pod_folder_name = "global_policies"

            pod_dir = os.path.join(self.output_dir, pod_folder_name)
            os.makedirs(pod_dir, exist_ok=True)

            name = policy["metadata"]["name"]
            filepath = os.path.join(pod_dir, f"{name}.yaml")

            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(policy, f, sort_keys=False)

            saved.append(filepath)

        print(f"Saved {len(saved)} policies to {self.output_dir}, organized by pod labels.")
        return saved



networkClass = NetworkCreatorClass("/home/kocm1/Network-policy-verification-in-Kubernetes/testbeds/istio-bookinfo/bookinfo.yaml")
networkClass.parse_kubernetes_yaml()
networkClass.generate_policies()
networkClass.save_policies()
