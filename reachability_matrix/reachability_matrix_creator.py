import yaml
from os import listdir

class ReachabilityMatrixCreator():
    def __init__(self, app_yaml_path, network_yaml_path):
        self.yaml_dict = []
        self.services = []
        self.pods_and_selectors = []
        self.network_policies = []
        self.reachability_matrix = {}

        self.yaml_parse(app_yaml_path)
        self.get_services_and_pods()
        self.match_pods_services()
        self.parse_network_yamls(network_yaml_path)
        self.match_pods_policies()
        self.create_reachability_matrix()
        self.to_reachability_table()
    
    def yaml_parse(self, yaml_path):
        with open(yaml_path, "r") as file:
            self.yaml_dict = list(yaml.safe_load_all(file))
    
    def get_services_and_pods(self):
        self.pods_and_selectors = []
        for component in self.yaml_dict:
            pod_name = component["metadata"]["name"]
            pod_namespace = component["metadata"].get("namespace") or "default"
            if component["kind"] == "Deployment" or component["kind"] == "StatefulSet":
                pod_labels = component["spec"]["template"]["metadata"]["labels"]
                ports = []
                for container in component["spec"]["template"]["spec"]["containers"]:
                    for port in container.get("ports") or []:
                        ports.append(port["containerPort"])
                self.pods_and_selectors.append({"pod_name": pod_name, "pod_namespace": pod_namespace, "pod_labels": pod_labels, "ports": ports})
            elif component["kind"] == "Pod":
                pod_labels = component["metadata"]["labels"]
                ports = []
                for container in component["spec"]["containers"]:
                    for port in container["ports"]:
                        ports.append(port["containerPort"])
                self.pods_and_selectors.append({"pod_name": pod_name, "pod_namespace": pod_namespace, "pod_labels": pod_labels, "ports": ports})
            elif component["kind"] == "Service":
                service_name = component["metadata"]["name"]
                service_namespace = component["metadata"]["namespace"]
                service_selectors = component["spec"]["selector"]
                ports = []
                for port in component["spec"]["ports"]:
                    ports.append({"port": port["port"], "targetPort": port.get("targetPort") or port["port"]})
                self.services.append({
                    "service_name": service_name,
                    "service_namespace": service_namespace,
                    "service_selectors": service_selectors,
                    "ports": ports
                })
            else:
                continue

    def parse_network_yamls(self, yaml_path):
        network_files = [network_file for network_file in listdir(yaml_path)]
        for network_file in network_files:
            with open(yaml_path+"/"+network_file) as file:
                yaml_dict = yaml.safe_load(file)
                policy_name = yaml_dict["metadata"]["name"]
                policy_namespace = yaml_dict["metadata"].get("namespace") or "default"
                policy_types = yaml_dict["spec"]["policyTypes"]
                pod_selectors = yaml_dict["spec"]["podSelector"].get("matchLabels") or {} 
                policy_rules = []
                for egress_rule in yaml_dict["spec"].get("egress") or []:
                    rule_type = "Egress"
                    selectors = []
                    target_ports = egress_rule["ports"]
                    for selector in egress_rule["to"]:
                        if selector.get("namespaceSelector"):
                            selector_type = "namespaceSelector"
                            labels = selector["namespaceSelector"]["matchLabels"]
                            selectors.append({"selector_type": selector_type, "labels": labels})
                        elif selector.get("podSelector"):
                            selector_type = "podSelector"
                            labels = selector["podSelector"]["matchLabels"]
                            selectors.append({"selector_type": selector_type, "labels": labels})
                        else:
                            continue
                    policy_rules.append({
                        "rule_type": rule_type,
                        "selectors": selectors,
                        "target_ports": target_ports
                    })

                for ingress_rule in yaml_dict["spec"].get("ingress") or []:
                    rule_type = "Ingress"
                    selectors = []
                    target_ports = ingress_rule["ports"]
                    for selector in ingress_rule["from"]:
                        if selector.get("namespaceSelector"):
                            selector_type = "namespaceSelector"
                            labels = selector["namespaceSelector"]["matchLabels"]
                            selectors.append({"selector_type": selector_type, "labels": labels})
                        elif selector.get("podSelector"):
                            selector_type = "podSelector"
                            labels = selector["podSelector"]["matchLabels"]
                            selectors.append({"selector_type": selector_type, "labels": labels})
                        else:
                            continue
                    policy_rules.append({
                        "rule_type": rule_type,
                        "selectors": selectors,
                        "target_ports": target_ports
                    })
                
                self.network_policies.append(
                    {
                        "policy_name": policy_name,
                        "policy_namespace": policy_namespace,
                        "policy_types": policy_types,
                        "pod_selectors": pod_selectors,
                        "policy_rules": policy_rules
                    } 
                )

    def match_pods_services(self):
        for i in range(len(self.pods_and_selectors)):
            self.pods_and_selectors[i]["services"] = []
            pod = self.pods_and_selectors[i]
            for service in self.services:
                is_matching = True
                pod_selectors = service["service_selectors"]
                if service["service_namespace"] == pod["pod_namespace"]:
                    for target_key, target_value in pod_selectors.items():
                        if not target_key in pod["pod_labels"] or pod["pod_labels"][target_key] != target_value:
                            is_matching = False
                else:
                    is_matching = False
                if is_matching:
                    self.pods_and_selectors[i]["services"].append(service)
                

    def match_pods_policies(self):
        for i in range(len(self.pods_and_selectors)):
            self.pods_and_selectors[i]["network_policies"] = []
            pod = self.pods_and_selectors[i]
            for network_policy in self.network_policies:
                is_matching = True
                pod_selector = network_policy["pod_selectors"]
                if network_policy["policy_namespace"] == pod["pod_namespace"]:
                    for target_key, target_value in pod_selector.items():
                        if not target_key in pod["pod_labels"] or pod["pod_labels"][target_key] != target_value:
                            is_matching = False
                else:
                    is_matching = False
                if is_matching:
                    self.pods_and_selectors[i]["network_policies"].append(network_policy)


    def find_policy_targets(self, policy_rule, policy_namespace):
        policy_targets = []
        for pod in self.pods_and_selectors:
            is_matching = True
            namespace_selector_exist = False
            for selector in policy_rule["selectors"]:
                if selector["selector_type"] == "podSelector":
                    for label_key, label_value in selector["labels"].items():
                        if not label_key in pod["pod_labels"] or pod["pod_labels"][label_key] != label_value:
                            is_matching = False
                else:
                    for label_key, label_value in selector["labels"].items():
                        namespace_selector_exist = True
                        if pod["pod_namespace"] != label_value:
                            is_matching = False

            if not namespace_selector_exist and pod["pod_namespace"] != policy_namespace:
                is_matching = False
            if is_matching:
                policy_targets.append(pod)
        return policy_targets
                
                
    def create_reachability_matrix(self):
        for pod in self.pods_and_selectors:
            pod_key = f"{pod['pod_namespace']}/{pod['pod_name']}"
            if pod_key not in self.reachability_matrix:
                self.reachability_matrix[pod_key] = {}

            for target_pod in self.pods_and_selectors:
                target_key = f"{target_pod['pod_namespace']}/{target_pod['pod_name']}"
                self.reachability_matrix[pod_key][target_key] = []

                for network_policy in pod["network_policies"]:
                    for policy_rule in network_policy["policy_rules"]:
                        if policy_rule["rule_type"] == "Ingress":
                            policy_targets = self.find_policy_targets(policy_rule, network_policy["policy_namespace"])
                            if any(t["pod_name"] == target_pod["pod_name"] for t in policy_targets):
                                for port in policy_rule["target_ports"]:
                                    self.reachability_matrix[pod_key][target_key].append(port["port"])

                for network_policy in target_pod["network_policies"]:
                    for policy_rule in network_policy["policy_rules"]:
                        if policy_rule["rule_type"] == "Egress":
                            policy_targets = self.find_policy_targets(policy_rule, network_policy["policy_namespace"])
                            if any(t["pod_name"] == pod["pod_name"] for t in policy_targets):
                                for port in policy_rule["target_ports"]:
                                    self.reachability_matrix[pod_key][target_key].append(port["port"])

    def to_reachability_table(self):
        pods = list(self.reachability_matrix.keys())
        col_width = max(len(p) for p in pods) + 2

        header = " " * col_width + "".join(p.ljust(col_width) for p in pods)
        print(header)

        for receiver in pods:
            row = receiver.ljust(col_width)
            for sender in pods:
                cell = self.reachability_matrix[receiver][sender]
                value = 1 if len(cell) > 0 else 0
                row += str(value).ljust(col_width)
            print(row)



        
                    
    

if __name__ == "__main__":
    reachabilityMatrixCreator = ReachabilityMatrixCreator("./application/app.yaml", "./network_policies")