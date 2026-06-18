import yaml
import sys

CILIUM_KINDS = {
    "CiliumNetworkPolicy": True,
    "CiliumClusterwideNetworkPolicy": True,
}
CILIUM_NAMESPACE_NAME_KEYS = (
    "k8s:io.kubernetes.pod.namespace",
    "io.kubernetes.pod.namespace",
)
CILIUM_NAMESPACE_LABEL_PREFIX = "io.cilium.k8s.namespace.labels."


class Policy():
    def __init__(self, name, namespace, source_labels, rules, policy_types, is_clusterwide=False,
                 is_cilium=False):
        self.name = name
        self.namespace = namespace
        self.source_labels = source_labels
        self.rules = rules
        self.policy_types = policy_types
        self.is_clusterwide = is_clusterwide
        self.is_cilium = is_cilium


class PolicyRule():
    def __init__(self, policy_type, target_labels, namespace_label, ports, is_deny=False,
                 ip_block_cidr=None):
        self.policy_type = policy_type
        self.target_labels = target_labels
        self.namespace_label = namespace_label
        self.ports = ports
        self.is_deny = is_deny
        self.ip_block_cidr = ip_block_cidr


class Port():
    def __init__(self, portNumber, protocol, endPort=None):
        self.portNumber = portNumber
        self.protocol = protocol
        self.endPort = endPort

    def endpoint_token(self):
        """Return the port component used in matrix endpoint strings."""
        if self.endPort is not None:
            return f"{self.portNumber}-{self.endPort}"
        return str(self.portNumber)

    def contains(self, port):
        """Return True when a numeric port falls inside this port or range."""
        port_value = int(port)
        if self.endPort is None:
            return port_value == int(self.portNumber)
        return int(self.portNumber) <= port_value <= int(self.endPort)


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
            if not policy:
                continue
            kind = policy.get("kind")
            is_cilium = kind in CILIUM_KINDS
            is_k8s = kind == "NetworkPolicy"
            if not (is_k8s or is_cilium):
                continue

            is_clusterwide = kind == "CiliumClusterwideNetworkPolicy"
            name = policy["metadata"]["name"]
            namespace = policy["metadata"].get("namespace") or "default"
            spec = policy["spec"]

            if is_cilium:
                raw_source_labels = spec.get("endpointSelector", {}).get("matchLabels") or {}
                source_labels, _ = self.split_cilium_labels(raw_source_labels)
                rules, policy_types = self._parse_cilium_policy(spec)
            else:
                source_labels = spec.get("podSelector", {}).get("matchLabels") or {}
                policy_types = self._resolve_k8s_policy_types(spec)
                rules = self._parse_k8s_rules(spec, policy_types)

            self.network_policies.append(Policy(
                name, namespace, source_labels, rules, policy_types, is_clusterwide, is_cilium))

    def _resolve_k8s_policy_types(self, spec):
        """Apply Kubernetes defaults when policyTypes is omitted."""
        if "policyTypes" in spec:
            return list(spec["policyTypes"])
        policy_types = ["Ingress"]
        if spec.get("egress"):
            policy_types.append("Egress")
        return policy_types

    def _parse_k8s_rules(self, spec, policy_types):
        """Parse ingress/egress rules that match the effective policy types."""
        rules = []
        for policy_type, section_name in (("Ingress", "ingress"), ("Egress", "egress")):
            if policy_type not in policy_types:
                continue
            for rule in spec.get(section_name) or []:
                self._append_rule(rules, policy_type, rule, is_cilium=False, is_deny=False)
        return rules

    def _parse_cilium_policy(self, spec):
        """Parse all Cilium rule sections and derive policy types from present sections."""
        rules = []
        policy_types = []
        sections = (
            ("Ingress", "ingress", False),
            ("Egress", "egress", False),
            ("Ingress", "ingressDeny", True),
            ("Egress", "egressDeny", True),
        )
        for policy_type, section_name, is_deny in sections:
            if spec.get(section_name) is None:
                continue
            if policy_type not in policy_types:
                policy_types.append(policy_type)
            for rule in spec.get(section_name) or []:
                self._append_rule(rules, policy_type, rule, is_cilium=True, is_deny=is_deny)
        if not policy_types and spec.get("endpointSelector") is not None:
            policy_types = ["Ingress", "Egress"]
        return rules, policy_types

    def _append_rule(self, rules, policy_type, rule, is_cilium, is_deny):
        all_targets = self.get_target_labels(policy_type, rule, is_cilium=is_cilium)
        ports = self.get_rule_ports(rule, policy_type, is_cilium=is_cilium)
        for target_labels, ns_label, ip_cidr in all_targets:
            rules.append(PolicyRule(
                policy_type, target_labels, ns_label, ports, is_deny,
                ip_block_cidr=ip_cidr,
            ))
        if rule == {}:
            rules.append(PolicyRule(policy_type, {}, {}, [], is_deny))
        elif len(all_targets) == 0:
            rules.append(PolicyRule(policy_type, {}, {}, ports, is_deny))

    def get_target_labels(self, policy_type, rule, is_cilium=False):
        if rule == {}:
            return [({}, {}, None)] if is_cilium else []
        if is_cilium:
            endpoint_key = "fromEndpoints" if policy_type == "Ingress" else "toEndpoints"
            cidr_key = "fromCIDR" if policy_type == "Ingress" else "toCIDR"
            results = []
            for endpoint in rule.get(endpoint_key) or []:
                if not endpoint or (not endpoint.get("matchLabels") and not endpoint.get("matchExpressions")):
                    results.append(({}, {}, None))
                    continue
                target_labels, namespace_label = self.split_cilium_labels(endpoint.get("matchLabels") or {})
                results.append((target_labels, namespace_label, None))
            for cidr in rule.get(cidr_key) or []:
                results.append(({}, {}, cidr))
            return results
        labels = rule.get("from", []) if policy_type == "Ingress" else rule.get("to", [])
        results = []
        for label in labels:
            if label.get("ipBlock"):
                results.append(({}, {}, label["ipBlock"].get("cidr")))
            else:
                results.append((
                    label.get("podSelector", {}).get("matchLabels", {}),
                    label.get("namespaceSelector", {}).get("matchLabels", {}),
                    None,
                ))
        return results

    def _parse_port_number(self, value):
        """Parse a Kubernetes/Cilium port field into an integer."""
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        raise ValueError(f"Unsupported port value: {value!r}")

    def _parse_port_entry(self, port, protocol=None):
        """Parse a single port or port range from a policy rule."""
        if isinstance(port, int):
            return Port(port, protocol or "TCP")
        if isinstance(port, str):
            port_number = port.split(":")[0] if ":" in port else port
            return Port(self._parse_port_number(port_number), protocol or "TCP")
        port_number = self._parse_port_number(port["port"])
        end_port = port.get("endPort")
        if end_port is not None:
            end_port = self._parse_port_number(end_port)
        return Port(port_number, port.get("protocol") or protocol or "TCP", endPort=end_port)

    def get_rule_ports(self, rule, policy_type, is_cilium=False):
        if is_cilium:
            port_entries = []
            for to_port in rule.get("toPorts") or []:
                port_entries.extend(to_port.get("ports") or [])
        else:
            port_entries = rule.get("ports") or []

        ports = []
        for port in port_entries:
            ports.append(self._parse_port_entry(port))
        return ports

    def split_cilium_labels(self, match_labels):
        labels = dict(match_labels or {})
        namespace_label = {}
        for key in list(labels.keys()):
            if key in CILIUM_NAMESPACE_NAME_KEYS:
                namespace_label["kubernetes.io/metadata.name"] = labels.pop(key)
            elif key.startswith(CILIUM_NAMESPACE_LABEL_PREFIX):
                namespace_label[key[len(CILIUM_NAMESPACE_LABEL_PREFIX):]] = labels.pop(key)
        return labels, namespace_label

    def print_network_policy(self):
        for policy in self.network_policies:
            print(
                f"Policy Name: {policy.name}\n"
                f"Policy Namespace: {policy.namespace}\n"
                f"Source Labels: {policy.source_labels}\n"
                f"Policy Types: {policy.policy_types}\n"
                f"Is Clusterwide: {policy.is_clusterwide}\n"
                f"Is Cilium: {policy.is_cilium}"
            )
            print("Rules:")
            for rule in policy.rules:
                print(f"\tPolicy Type: {rule.policy_type}\n\tIs Deny: {rule.is_deny}\n\tTarget Labels: {rule.target_labels}\n\tNamespace Label: {rule.namespace_label}")
                if rule.ip_block_cidr:
                    print(f"\tIP Block CIDR: {rule.ip_block_cidr}")
                print("\tPorts")
                for port in rule.ports:
                    if port.endPort is not None:
                        print(f"\t\tPort Range: {port.portNumber}-{port.endPort}\n\t\tPort Protocol: {port.protocol}")
                    else:
                        print(f"\t\tPort Number: {port.portNumber}\n\t\tPort Protocol: {port.protocol}")
                print()
            print()


if __name__ == "__main__":
    policy_file_path = "./network_policies/example.yaml"
    if len(sys.argv) == 2:
        policy_file_path = sys.argv[1]
    parser = PolicyParser(policy_file_path)
    parser.print_network_policy()
