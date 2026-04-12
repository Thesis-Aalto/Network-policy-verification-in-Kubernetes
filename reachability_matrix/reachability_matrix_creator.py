import yaml
from os import listdir

class ReachabilityMatrixCreator():
    def __init__(self, app_yaml_path, network_yaml_path):
        self.yaml_dict = []
        self.pods_and_selectors = []
        self.network_policies = []

        self.yaml_parse(app_yaml_path)
        self.get_pods_and_selectors()
        self.parse_network_yamls(network_yaml_path)
    
    def yaml_parse(self, yaml_path):
        with open(yaml_path, "r") as file:
            self.yaml_dict = list(yaml.safe_load_all(file))
    
    def get_pods_and_selectors(self):
        self.pods_and_selectors = []
        for component in self.yaml_dict:
            pod_name = component["metadata"]["name"]
            pod_namespace = component["metadata"].get("namespace") or "default"
            if component["kind"] == "Deployment" or component["kind"] == "StatefulSet":
                pod_labels = component["spec"]["template"]["metadata"]["labels"]
                self.pods_and_selectors.append({"pod_name": pod_name, "pod_namespace": pod_namespace, "pod_labels": pod_labels})
            elif component["kind"] == "Pod":
                pod_labels = component["metadata"]["labels"]
                self.pods_and_selectors.append({"pod_name": pod_name, "pod_namespace": pod_namespace, "pod_labels": pod_labels})
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
                pod_selectors = yaml_dict["spec"]["podSelector"]
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
 

if __name__ == "__main__":
    reachabilityMatrixCreator = ReachabilityMatrixCreator("./application/app.yaml", "./network_policies")