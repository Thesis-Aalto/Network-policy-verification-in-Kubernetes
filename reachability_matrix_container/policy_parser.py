import os
import yaml

CILIUM_KINDS = frozenset({"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy"})
SUPPORTED_POLICY_KINDS = CILIUM_KINDS | {"NetworkPolicy"}
CILIUM_NAMESPACE_LABEL_KEYS = (
    "k8s:io.kubernetes.pod.namespace",
    "io.kubernetes.pod.namespace",
)

class Policy():
    def __init__(self, name, namespace, source_labels, rules, policy_types):
        self.name = name
        self.namespace = namespace
        self.source_labels = source_labels
        self.rules = rules
        self.policy_types = policy_types

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
            if not policy or policy.get("kind") not in SUPPORTED_POLICY_KINDS:
                continue
            is_cilium = policy["kind"] in CILIUM_KINDS
            name = policy["metadata"]["name"]
            namespace = policy["metadata"].get("namespace") or "default"
            spec = policy["spec"]
            if is_cilium:
                raw_source_labels = spec.get("endpointSelector", {}).get("matchLabels") or {}
                if policy["kind"] == "CiliumClusterwideNetworkPolicy":
                    source_labels, namespace = self._split_cilium_labels(raw_source_labels, namespace)
                else:
                    source_labels = raw_source_labels
            else:
                source_labels = spec.get("podSelector", {}).get("matchLabels") or {}
            rules = []
            policy_types = []
            for policy_type in ["Ingress", "Egress"]:
                if policy_type.lower() in spec:
                    policy_types.append(policy_type)
                    for rule in spec.get(policy_type.lower()) or []:
                        all_targets = self.get_target_labels(policy_type, rule, namespace, is_cilium)
                        ports = self._get_rule_ports(rule, is_cilium)
                        for target_labels, namespace_label in all_targets:
                            new_rule = PolicyRule(policy_type, target_labels, namespace_label, ports)
                            rules.append(new_rule)
                        if rule == {}:
                            new_rule = PolicyRule(policy_type, {}, {}, [])
                            rules.append(new_rule)
                        #Case when there are no selectors and only ports
                        elif len(all_targets) == 0:
                            new_rule = PolicyRule(policy_type, {}, {}, ports)
                            rules.append(new_rule)
                            
            new_network_policy = Policy(name, namespace, source_labels, rules, policy_types)
            self.network_policies.append(new_network_policy)

    def get_target_labels(self, policy_type, rule, namespace, is_cilium=False):
        results = []
        if rule == {}:
            return results
        if is_cilium:
            labels = rule.get("fromEndpoints", []) if policy_type == "Ingress" else rule.get("toEndpoints", [])
            for endpoint in labels:
                target_labels, namespace_label = self._split_cilium_labels(
                    endpoint.get("matchLabels", {}), namespace
                )
                results.append((target_labels, namespace_label))
            return results
        labels = rule.get("from", []) if policy_type == "Ingress" else rule.get("to", [])
        for label in labels:
            pod_selector = label.get("podSelector", {}).get("matchLabels", {})
            namespace_selector = label.get("namespaceSelector", {}).get("matchLabels", {})
            target_labels = dict(pod_selector)
            namespace_label = next(iter(namespace_selector.values()), namespace)
            results.append((target_labels, namespace_label))
        return results

    def _split_cilium_labels(self, match_labels, default_namespace):
        labels = dict(match_labels)
        namespace_label = default_namespace
        for key in CILIUM_NAMESPACE_LABEL_KEYS:
            if key in labels:
                namespace_label = labels.pop(key)
        return labels, namespace_label

    def _get_rule_ports(self, rule, is_cilium):
        ports = []
        if is_cilium:
            port_entries = []
            for to_port in rule.get("toPorts") or []:
                port_entries.extend(to_port.get("ports") or [])
        else:
            port_entries = rule.get("ports") or []
        for port in port_entries:
            port_number = port["port"]
            if isinstance(port_number, str) and port_number.isdigit():
                port_number = int(port_number)
            protocol = port.get("protocol") or "TCP"
            ports.append(Port(port_number, protocol))
        return ports

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

    