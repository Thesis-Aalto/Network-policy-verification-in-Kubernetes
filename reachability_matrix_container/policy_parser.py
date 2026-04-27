import os
import yaml

class Policy():
    def __init__(self, name, namespace, source_labels, rules):
        self.name = name
        self.namespace = namespace
        self.source_labels = source_labels
        self.rules = rules

class PolicyRule():
    def __init__(self, policy_type, target_labels, namespace_label, ports):
        self.policy_type = policy_type
        self.target_labels = target_labels
        self.namespace_label = namespace_label
        self.ports = ports

class Port():
    def __init__(self, portNumber, protocol):
        self.portNumber = portNumber
        self.protocol = protocol

class PolicyParser():
    def __init__(self, policy_path):
        self.network_policies = []
        self.parse_policies(policy_path)

    def parse_policies(self, policy_path):
        for file in os.listdir(policy_path):
            with open(policy_path+"/"+file, "r") as file:
                parsed_yaml = list(yaml.safe_load_all(file))
                network_policy = self.get_network_policy(parsed_yaml)

    def get_network_policy(self, parsed_yaml):
        for policy in parsed_yaml:
            name = policy["metadata"]["name"]
            namespace = policy["metadata"].get("namespace") or "default"
            source_labels = policy["spec"]["podSelector"].get("matchLabels") or {}
            rules = []
            for policy_type in policy["spec"]["policyTypes"]:
                for rule in policy["spec"][policy_type.lower()]:
                    target_labels, namespace_labels = self.get_target_labels(policy_type, rule)                 
                    ports = []
                    for port in rule["ports"]:
                        portNumber = port["port"]
                        protocol = port.get("protocol") or "TCP"
                        new_port = Port(portNumber, protocol)
                        ports.append(new_port)
                    new_rule = PolicyRule(policy_type, target_labels, namespace_labels, ports)
                    rules.append(new_rule)
            new_network_policy = Policy(name, namespace, source_labels, rules)
            self.network_policies.append(new_network_policy)

    def get_target_labels(self, policy_type, rule):
        target_labels = {}
        namespace_label = "default"
        labels = {}
        if policy_type == "Ingress":
            labels = rule["from"]
        else:
            labels = rule["to"]
        for label in labels:
            pod_selector = label.get("podSelector", {}).get("matchLabels", {})
            namespace_selector = label.get("namespaceSelector", {}).get("matchLabels", {})
            if pod_selector != {}:
                for key, item in pod_selector.items():
                    target_labels[key] = item
            if namespace_selector != {}:
                for key, item in namespace_selector.items():
                    namespace_label = item
        return target_labels, namespace_label

    def print_network_policy(self):
        for policy in self.network_policies:
            print(f"Policy Name: {policy.name}\nPolicy Namespace: {policy.namespace}\nSource Labels: {policy.source_labels}")
            print("Rules:")
            for rule in policy.rules:
                print(f"\tPolicy Type: {rule.policy_type}\n\tTarget Labels:{rule.target_labels}")
                print("\tPorts")
                for port in rule.ports:
                    print(f"\t\tPort Number: {port.portNumber}\n\t\tPort Protocol: {port.protocol}")
                print()
            print()      


if __name__ == "__main__":
    parser = PolicyParser("./network_policies")
    parser.print_network_policy()

    