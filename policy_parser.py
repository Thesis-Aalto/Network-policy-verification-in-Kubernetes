import yaml
import sys

CALICO_API_PREFIX = "projectcalico.org/"
CILIUM_KINDS = {
    "CiliumNetworkPolicy": True,
    "CiliumClusterwideNetworkPolicy": True,
}
CALICO_KINDS = {
    "NetworkPolicy": True,
    "GlobalNetworkPolicy": True,
}
CILIUM_NAMESPACE_NAME_KEYS = (
    "k8s:io.kubernetes.pod.namespace",
    "io.kubernetes.pod.namespace",
)
CILIUM_NAMESPACE_LABEL_PREFIX = "io.cilium.k8s.namespace.labels."


class Policy():
    def __init__(self, name, namespace, source_labels, rules, policy_types, is_clusterwide=False,
                 endpoint_namespaces=None, is_cilium=False, is_calico=False):
        self.name = name
        self.namespace = namespace
        self.source_labels = source_labels
        self.rules = rules
        self.policy_types = policy_types
        self.is_clusterwide = is_clusterwide
        self.endpoint_namespaces = endpoint_namespaces or []
        self.is_cilium = is_cilium
        self.is_calico = is_calico

    def uses_cross_namespace_peers(self):
        return self.is_clusterwide or self.is_cilium or self.is_calico


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
            if not policy:
                continue
            kind = policy.get("kind")
            api_version = policy.get("apiVersion", "")
            is_calico = api_version.startswith(CALICO_API_PREFIX) and kind in CALICO_KINDS
            is_cilium = kind in CILIUM_KINDS
            is_k8s = kind == "NetworkPolicy" and not is_calico
            if not (is_k8s or is_cilium or is_calico):
                continue

            is_clusterwide = kind in {"CiliumClusterwideNetworkPolicy", "GlobalNetworkPolicy"}
            name = policy["metadata"]["name"]
            namespace = policy["metadata"].get("namespace") or "default"
            spec = policy["spec"]
            endpoint_namespaces = []
            rules = []
            policy_types = []

            if is_calico:
                source_labels = self.parse_calico_selector(spec.get("selector"))
                namespace_label = self.parse_calico_selector(spec.get("namespaceSelector"))
                if "kubernetes.io/metadata.name" in namespace_label:
                    endpoint_namespaces = [namespace_label["kubernetes.io/metadata.name"]]
                policy_types = list(spec.get("types") or [])
                for policy_type, section_name in [("Ingress", "ingress"), ("Egress", "egress")]:
                    if section_name not in spec:
                        continue
                    if policy_type not in policy_types:
                        policy_types.append(policy_type)
                    for rule in spec.get(section_name) or []:
                        is_deny = rule.get("action", "Allow") == "Deny"
                        all_targets = self.get_target_labels(policy_type, rule, is_calico=True)
                        ports = self.get_rule_ports(rule, policy_type, is_calico=True)
                        for target_labels, ns_label, ip_cidr in all_targets:
                            rules.append(PolicyRule(
                                policy_type, target_labels, ns_label, ports, is_deny,
                                ip_block_cidr=ip_cidr,
                            ))
            else:
                if is_cilium:
                    raw_source_labels = spec.get("endpointSelector", {}).get("matchLabels") or {}
                    source_labels, source_namespace_label = self.split_cilium_labels(raw_source_labels)
                    if "kubernetes.io/metadata.name" in source_namespace_label:
                        namespace = source_namespace_label["kubernetes.io/metadata.name"]
                        endpoint_namespaces = [namespace]
                else:
                    source_labels = spec.get("podSelector", {}).get("matchLabels") or {}

                rule_sections = [
                    ("Ingress", "ingress", False),
                    ("Egress", "egress", False),
                    ("Ingress", "ingressDeny", True),
                    ("Egress", "egressDeny", True),
                ]
                for policy_type, section_name, is_deny in rule_sections:
                    if is_cilium:
                        if spec.get(section_name) is None:
                            continue
                        if policy_type not in policy_types:
                            policy_types.append(policy_type)
                    else:
                        if is_deny:
                            continue
                        if policy_type not in spec.get("policyTypes", []):
                            continue
                        policy_types.append(policy_type)
                    for rule in spec.get(section_name) or []:
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
                if is_cilium and not policy_types:
                    policy_types = ["Ingress", "Egress"]

            if is_calico and not policy_types and (spec.get("ingress") is not None or spec.get("egress") is not None):
                policy_types = ["Ingress", "Egress"]

            self.network_policies.append(Policy(
                name, namespace, source_labels, rules, policy_types, is_clusterwide,
                endpoint_namespaces, is_cilium, is_calico))

    def parse_calico_selector(self, selector):
        if not selector or str(selector).strip() in {"all()", ""}:
            return {}
        labels = {}
        for part in str(selector).split("&&"):
            part = part.strip()
            if "==" not in part:
                continue
            key, value = part.split("==", 1)
            labels[key.strip()] = value.strip().strip("'\"")
        return labels

    def get_target_labels(self, policy_type, rule, is_cilium=False, is_calico=False):
        if is_calico:
            entity = (rule.get("source") or {}) if policy_type == "Ingress" else (rule.get("destination") or {})
            return [(
                self.parse_calico_selector(entity.get("selector")),
                self.parse_calico_selector(entity.get("namespaceSelector")),
                None,
            )]
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

    def get_rule_ports(self, rule, policy_type, is_cilium=False, is_calico=False):
        if is_calico:
            protocol = rule.get("protocol") or "TCP"
            entity = (rule.get("destination") or {}) if policy_type == "Ingress" else (rule.get("destination") or {})
            port_entries = entity.get("ports") or []
        elif is_cilium:
            port_entries = []
            for to_port in rule.get("toPorts") or []:
                port_entries.extend(to_port.get("ports") or [])
        else:
            port_entries = rule.get("ports") or []

        ports = []
        for port in port_entries:
            if is_calico:
                port_number = port.split(":")[0] if isinstance(port, str) else port
                if isinstance(port_number, str) and port_number.isdigit():
                    port_number = int(port_number)
                protocol = rule.get("protocol") or "TCP"
            else:
                port_number = port["port"]
                if isinstance(port_number, str) and port_number.isdigit():
                    port_number = int(port_number)
                protocol = port.get("protocol") or "TCP"
            ports.append(Port(port_number, protocol))
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
            print(f"Policy Name: {policy.name}\nPolicy Namespace: {policy.namespace}\nSource Labels: {policy.source_labels}\nPolicy Types: {policy.policy_types}")
            print("Rules:")
            for rule in policy.rules:
                print(f"\tPolicy Type: {rule.policy_type}\n\tIs Deny: {rule.is_deny}\n\tTarget Labels: {rule.target_labels}\n\tNamespace Label: {rule.namespace_label}")
                if rule.ip_block_cidr:
                    print(f"\tIP Block CIDR: {rule.ip_block_cidr}")
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
