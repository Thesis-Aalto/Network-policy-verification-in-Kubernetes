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
        self.parse_network_yamls(network_yaml_path)
        self.match_pods_policies()
        #self.create_reachability_matrix()
    
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
                service_selector = component["spec"]["selector"]
                ports = []
                for port in component["spec"]["ports"]:
                    ports.append({"port": port["port"], "targetPort": port.get("targetPort") or port["port"]})
                self.services.append({
                    "service_name": service_name,
                    "service_namespace": service_namespace,
                    "service_selector": service_selector,
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
                
                self.network_policies.append(
                    {
                        "policy_name": policy_name,
                        "policy_namespace": policy_namespace,
                        "policy_types": policy_types,
                        "pod_selectors": pod_selectors,
                        "policy_rules": policy_rules
                    } 
                )

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
    """

    def find_policy_targets(self, policy_rule):
        target_pods = []
        for pod in self.pods_and_selectors:
            if network_policy["policy_namespace"] == pod["pod_namespace"]:
                



    def create_reachability_matrix(self):
        for pod in self.pods_and_selectors:
            for network_policy in  pod["network_policies"]:
                for policy_rule in network_policy["policy_rules"]:
                    if policy_rule["rule_type"] == "Ingress":
                        policy_targets = self.find_policy_targets(policy_rule, network_policy["policy_namespace"])

                    else:
    """

        
                    
    

if __name__ == "__main__":
    reachabilityMatrixCreator = ReachabilityMatrixCreator("./application/app.yaml", "./network_policies")