import yaml
import itertools
import os

class NetworkPolicyCreator():
    def __init__(self, yaml_path, max_subset=2, output_dir="./network_policies"):
        self.yaml_path = yaml_path
        self.max_subset = max_subset
        self.workloads = dict()
        self.services = dict()
        self.policies = []
        self.output_dir = output_dir

        self._setup()

    def _setup(self):
        self._parse_kubernetes_yaml()
        self._generate_default_policies()
        #self.save_default_policies()
        self._generate_policies()
        #self.save_policies()
    def get_workloads(self):
        return self.workloads
    def _parse_kubernetes_yaml(self):
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
                {"port": p["targetPort"], "protocol": p["protocol"]}
                for p in workload["service"]["ports"]
                if p.get("targetPort")
            ]
        return []

    def _generate_policies(self):
        workload_list = list(self.workloads.values())

        # 1. Generate Egress Policies (One Source -> Multiple Destinations)
        for source in workload_list:
            destinations = [w for w in workload_list if w["name"] != source["name"]]
            for size in range(1, self.max_subset + 1):
                for subset in itertools.combinations(destinations, size):
                    self._generate_egress_policy(source, list(subset))

        # 2. Generate Ingress Policies (Multiple Sources -> One Destination)
        for dest in workload_list:
            sources = [w for w in workload_list if w["name"] != dest["name"]]
            for size in range(1, self.max_subset + 1):
                for subset in itertools.combinations(sources, size):
                    self._generate_ingress_policy(dest, list(subset))

        return self.policies

    def _generate_egress_policy(self, source, dest_subset):
        egress_rules = []
        for dest in dest_subset:
            ports = self._get_policy_ports(dest)
            rule = {"to": [{"podSelector": {"matchLabels": dest["pod_labels"]}}]}
            if ports:
                rule["ports"] = [{"protocol": p["protocol"], "port": p["port"]} for p in ports]
            egress_rules.append(rule)

        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": self._policy_name("egress", source, dest_subset)},
            "spec": {
                "podSelector": {"matchLabels": source["pod_labels"]},
                "policyTypes": ["Egress"],
                "egress": egress_rules,
            },
        }
        self.policies.append(policy)

    def _generate_ingress_policy(self, dest, source_subset):
        """Creates one policy for a destination that allows traffic FROM many sources."""
        ports = self._get_policy_ports(dest)
        
        # Build the 'from' list containing multiple source podSelectors
        ingress_from = [
            {"podSelector": {"matchLabels": src["pod_labels"]}} 
            for src in source_subset
        ]

        ingress_rule = {"from": ingress_from}
        if ports:
            ingress_rule["ports"] = [{"protocol": p["protocol"], "port": p["port"]} for p in ports]

        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": self._policy_name("ingress", dest, source_subset)},
            "spec": {
                "podSelector": {"matchLabels": dest["pod_labels"]},
                "policyTypes": ["Ingress"],
                "ingress": [ingress_rule],
            },
        }
        self.policies.append(policy)

    def _policy_name(self, direction, primary, subset):
        subset_names = "-".join(s["name"] for s in subset)
        if direction == "egress":
            name = f"egress-{primary['name']}-to-{subset_names}"
        else:
            name = f"ingress-{primary['name']}-from-{subset_names}"
        return name[:63].rstrip("-")
    
    def _save_policies(self):
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

    def _generate_default_policies(self):
        deny_all = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }
        allow_dns = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "allow-dns"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "ports": [
                            {"protocol": "UDP", "port": 53},
                            {"protocol": "TCP", "port": 53},
                        ]
                    }
                ],
            },
        }
        return [deny_all, allow_dns]
 
    def _save_default_policies(self):
        defaults = self.generate_default_policies()
        saved = []
        defaults_dir = os.path.join(self.output_dir, "default")
        os.makedirs(defaults_dir, exist_ok=True)
        for policy in defaults:
            name = policy["metadata"]["name"]
            filepath = os.path.join(defaults_dir, f"{name}.yaml")
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(policy, f, sort_keys=False)
            saved.append(filepath)
        print(f"Saved {len(saved)} default policies to {defaults_dir}.")
        return saved


