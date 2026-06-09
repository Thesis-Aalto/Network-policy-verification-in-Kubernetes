import os
import yaml
import sys

CILIUM_KINDS = frozenset({"CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy"})
SUPPORTED_POLICY_KINDS = CILIUM_KINDS | {"NetworkPolicy"}
CILIUM_NAMESPACE_NAME_KEYS = (
    "k8s:io.kubernetes.pod.namespace",
    "io.kubernetes.pod.namespace",
)
CILIUM_NAMESPACE_LABEL_PREFIX = "io.cilium.k8s.namespace.labels."

class Policy():
    def __init__(self, name, namespace, source_labels, rules, policy_types, is_clusterwide=False,
                 endpoint_namespaces=None):
        self.name = name
        self.namespace = namespace
        self.source_labels = source_labels
        self.rules = rules
        self.policy_types = policy_types
        self.is_clusterwide = is_clusterwide
        self.endpoint_namespaces = endpoint_namespaces or []

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
        with open(policy_path, "r") as f:
            parsed_yaml = list(yaml.safe_load_all(f))
            self.get_network_policy(parsed_yaml)

    def get_network_policy(self, parsed_yaml):
        for policy in parsed_yaml:
            if not policy or policy.get("kind") not in SUPPORTED_POLICY_KINDS:
                continue
            is_cilium = policy["kind"] in CILIUM_KINDS
            is_clusterwide = policy["kind"] == "CiliumClusterwideNetworkPolicy"
            name = policy["metadata"]["name"]
            namespace = policy["metadata"].get("namespace") or "default"
            spec = policy["spec"]
            endpoint_namespaces = []
            if is_cilium:
                raw_source_labels = spec.get("endpointSelector", {}).get("matchLabels") or {}
                source_labels, source_namespace_label = self.split_cilium_labels(raw_source_labels)
                if "kubernetes.io/metadata.name" in source_namespace_label:
                    namespace = source_namespace_label["kubernetes.io/metadata.name"]
                    endpoint_namespaces = [namespace]
            else:
                source_labels = spec.get("podSelector", {}).get("matchLabels") or {}
            rules = []
            policy_types = []
            for policy_type in ["Ingress", "Egress"]:
                if is_cilium:
                    if spec.get(policy_type.lower()) is None:
                        continue
                    policy_types.append(policy_type)
                elif policy_type not in spec.get("policyTypes", []):
                    continue
                else:
                    policy_types.append(policy_type)
                for rule in spec.get(policy_type.lower()) or []:
                    all_targets = self.get_target_labels(policy_type, rule, is_cilium)
                    ports = self.get_rule_ports(rule, is_cilium)
                    for target_labels, namespace_label in all_targets:
                        new_rule = PolicyRule(policy_type, target_labels, namespace_label, ports)
                        rules.append(new_rule)
                    if rule == {}:
                        new_rule = PolicyRule(policy_type, {}, {}, [])
                        rules.append(new_rule)
                    elif len(all_targets) == 0:
                        new_rule = PolicyRule(policy_type, {}, {}, ports)
                        rules.append(new_rule)
            if is_cilium and not policy_types:
                policy_types = ["Ingress", "Egress"]

            new_network_policy = Policy(
                name, namespace, source_labels, rules, policy_types, is_clusterwide, endpoint_namespaces)
            self.network_policies.append(new_network_policy)

    def get_target_labels(self, policy_type, rule, is_cilium=False):
        results = []
        if rule == {}:
            return [({}, {})] if is_cilium else results
        if is_cilium:
            endpoint_key = "fromEndpoints" if policy_type == "Ingress" else "toEndpoints"
            for endpoint in rule.get(endpoint_key) or []:
                if not endpoint or (not endpoint.get("matchLabels") and not endpoint.get("matchExpressions")):
                    results.append(({}, {}))
                    continue
                target_labels, namespace_label = self.split_cilium_labels(endpoint.get("matchLabels") or {})
                results.append((target_labels, namespace_label))
            return results
        labels = rule.get("from", []) if policy_type == "Ingress" else rule.get("to", [])
        for label in labels:
            pod_selector = label.get("podSelector", {}).get("matchLabels", {})
            namespace_selector = label.get("namespaceSelector", {}).get("matchLabels", {})
            target_labels = dict(pod_selector)
            namespace_label = dict(namespace_selector)
            results.append((target_labels, namespace_label))
        return results

    def split_cilium_labels(self, match_labels):
        labels = dict(match_labels or {})
        namespace_label = {}
        for key in list(labels.keys()):
            if key in CILIUM_NAMESPACE_NAME_KEYS:
                namespace_label["kubernetes.io/metadata.name"] = labels.pop(key)
            elif key.startswith(CILIUM_NAMESPACE_LABEL_PREFIX):
                namespace_label[key[len(CILIUM_NAMESPACE_LABEL_PREFIX):]] = labels.pop(key)
        return labels, namespace_label

    def get_rule_ports(self, rule, is_cilium):
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
            print(f"Policy Name: {policy.name}\nPolicy Namespace: {policy.namespace}\nSource Labels: {policy.source_labels}\nPolicy Types: {policy.policy_types}")
            print("Rules:")
            for rule in policy.rules:
                print(f"\tPolicy Type: {rule.policy_type}\n\tTarget Labels: {rule.target_labels}\n\tNamespace Label: {rule.namespace_label}")
                print("\tPorts")
                for port in rule.ports:
                    print(f"\t\tPort Number: {port.portNumber}\n\t\tPort Protocol: {port.protocol}")
                print()
            print()      


if __name__ == "__main__":
    policy_file_path = "./network_policies/example.yaml"
    if len(sys.argv) == 2:
        policy_file_path = sys.argv[1]
    parser = PolicyParser(policy_file_path)
    parser.print_network_policy()
