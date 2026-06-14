from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer

import sys
import pandas as pd

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 2000)

WILDCARD = "*"
KNOWN_PROTOCOLS = frozenset({"TCP", "UDP", "SCTP"})
ENDPOINT_SEP = "_"


class ReachabilityCreator():
    """
    Builds a reachability matrix from Kubernetes network policies and cluster topology.

    Rows are traffic sources and columns are destinations. Values are 1 (allowed) or 0 (denied).
    Endpoints use fixed format namespace_workload_port_protocol with '*' wildcards, e.g.
    backend-ns_makeline-service_*_* or database-ns_*_5672_TCP. Cilium clusterwide and Calico
    GlobalNetworkPolicy use *_workload_port_protocol where the first wildcard is the namespace.

    Ingress and egress are tracked separately, then combined with element-wise multiplication:
    reachability = egress_matrix * ingress_matrix
    """

    def __init__(self, services, workloads, namespaces, network_policies):
        self.services = services
        self.workloads = workloads
        self.namespaces = namespaces
        self.network_policies = network_policies

        self.ingress_matrix = self.initialize_matrix()
        self.egress_matrix = self.initialize_matrix()
        self.is_policy_applied = {}
        self.reachability_matrix = pd.DataFrame()

    def create_reachability_matrix(self):
        for policy in self.network_policies:
            self.apply_network_policy(policy, phase="allow")
        for policy in self.network_policies:
            if len(policy.rules) == 0:
                self.apply_network_policy(policy, phase="default")
        for policy in self.network_policies:
            self.apply_network_policy(policy, phase="deny")
        self.intersect_egress_and_igress()
        return self.reachability_matrix

    def initialize_matrix(self):
        new_matrix = pd.DataFrame()
        for source_namespace in self.namespaces:
            for target_namespace in self.namespaces:
                new_matrix.at[source_namespace.name, target_namespace.name] = 1
        return new_matrix

    def all_namespace_names(self):
        return [namespace.name for namespace in self.namespaces]

    def is_allow_all_rule(self, rule):
        return rule.target_labels == {} and rule.namespace_label == {} and len(rule.ports) == 0

    def _labels_match(self, labels, selector):
        return all(key in labels and labels[key] == value for key, value in selector.items())

    def _ingress_target_namespaces(self, policy):
        if policy.endpoint_namespaces:
            return policy.endpoint_namespaces
        if policy.is_clusterwide:
            return self.all_namespace_names()
        return [policy.namespace]

    def _match_namespace(self, endpoint):
        if endpoint == WILDCARD or endpoint.startswith(f"{WILDCARD}{ENDPOINT_SEP}"):
            return WILDCARD
        namespace_names = self.all_namespace_names()
        matches = [
            name for name in namespace_names
            if endpoint == name or endpoint.startswith(f"{name}{ENDPOINT_SEP}")
        ]
        if not matches:
            raise ValueError(f"Could not parse namespace from endpoint: {endpoint}")
        return max(matches, key=len)

    def _endpoint_namespace(self, namespace, clusterwide=False):
        return WILDCARD if clusterwide else namespace

    def _encode_endpoint(self, namespace, workload=WILDCARD, port=WILDCARD, protocol=WILDCARD, collapse_namespace=True):
        workload = str(workload) if workload != WILDCARD else WILDCARD
        port = str(port) if port != WILDCARD else WILDCARD
        if collapse_namespace and workload == WILDCARD and port == WILDCARD and protocol == WILDCARD:
            return namespace
        return ENDPOINT_SEP.join([namespace, workload, port, protocol])

    def _parse_endpoint(self, endpoint):
        namespace_names = self.all_namespace_names()
        if endpoint in namespace_names:
            return endpoint, WILDCARD, WILDCARD, WILDCARD

        namespace = self._match_namespace(endpoint)
        remainder = endpoint[len(namespace) + len(ENDPOINT_SEP):]
        parts = remainder.split(ENDPOINT_SEP) if remainder else []

        protocol = WILDCARD
        port = WILDCARD
        if parts and (parts[-1] in KNOWN_PROTOCOLS or parts[-1] == WILDCARD):
            protocol = parts.pop()
        if parts and (parts[-1] == WILDCARD or parts[-1].isdigit()):
            port = parts.pop()

        workload = WILDCARD
        if parts:
            workload = ENDPOINT_SEP.join(parts)
            if workload == "":
                workload = WILDCARD

        return namespace, workload, port, protocol

    def _endpoint_parent_chain(self, endpoint_name):
        namespace, workload, port, protocol = self._parse_endpoint(endpoint_name)
        parents = []
        current = (namespace, workload, port, protocol)
        while True:
            ns, wl, pt, pr = current
            if pr != WILDCARD:
                current = (ns, wl, pt, WILDCARD)
            elif pt != WILDCARD:
                current = (ns, wl, WILDCARD, WILDCARD)
            elif wl != WILDCARD:
                current = (ns, WILDCARD, WILDCARD, WILDCARD)
            else:
                break

            if current == (namespace, workload, port, protocol):
                break

            parent_ns, parent_wl, parent_pt, parent_pr = current
            collapse = parent_wl == WILDCARD and parent_pt == WILDCARD and parent_pr == WILDCARD
            if collapse and parent_ns == WILDCARD:
                break
            parents.append(self._encode_endpoint(
                parent_ns, parent_wl, parent_pt, parent_pr, collapse_namespace=collapse))
            specified = sum(value != WILDCARD for value in current[1:])
            if specified == 0:
                break
        return parents

    def _workload_endpoint(self, namespace, workload_name, clusterwide=False):
        return self._encode_endpoint(self._endpoint_namespace(namespace, clusterwide), workload_name)

    def _service_endpoint(self, namespace, service_identity, port=None, protocol=None, clusterwide=False):
        endpoint_namespace = self._endpoint_namespace(namespace, clusterwide)
        if port is None:
            return self._encode_endpoint(endpoint_namespace, service_identity)
        return self._encode_endpoint(endpoint_namespace, service_identity, port, protocol)

    def _namespace_port_endpoint(self, namespace, port, protocol, clusterwide=False):
        return self._encode_endpoint(self._endpoint_namespace(namespace, clusterwide), WILDCARD, port.portNumber, port.protocol)

    def apply_network_policy(self, policy, phase="allow"):
        clusterwide = policy.is_clusterwide
        if phase == "default":
            sources = {}
            source_namespaces = self.all_namespace_names() if clusterwide else [policy.namespace]
            if policy.source_labels == {}:
                for namespace_name in source_namespaces:
                    sources[namespace_name] = 1
                    for workload in self.workloads.get(namespace_name, []):
                        sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1
            else:
                for namespace_name in source_namespaces:
                    for workload in self.workloads.get(namespace_name, []):
                        if self._labels_match(workload.labels, policy.source_labels):
                            sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1
            for policy_type in policy.policy_types:
                self.fill_matrix(sources, {}, policy_type, policy.namespace)
            return

        if len(policy.rules) == 0:
            return

        for rule in policy.rules:
            if phase == "allow" and rule.is_deny:
                continue
            if phase == "deny" and not rule.is_deny:
                continue

            sources = {}
            targets = {}
            allow_all = self.is_allow_all_rule(rule)

            if rule.namespace_label:
                targeted_namespaces = [
                    namespace.name
                    for namespace in self.namespaces
                    if self._labels_match(namespace.labels, rule.namespace_label)
                ]
            elif clusterwide or policy.uses_cross_namespace_peers():
                targeted_namespaces = self.all_namespace_names()
            else:
                targeted_namespaces = [policy.namespace]

            source_namespaces = self.all_namespace_names() if clusterwide else [policy.namespace]

            if rule.policy_type == "Egress":
                if policy.source_labels == {}:
                    for namespace_name in source_namespaces:
                        sources[namespace_name] = 1
                else:
                    for namespace_name in source_namespaces:
                        for workload in self.workloads.get(namespace_name, []):
                            if self._labels_match(workload.labels, policy.source_labels):
                                sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1

                if allow_all:
                    for namespace_name in self.all_namespace_names():
                        targets[namespace_name] = 1
                elif rule.target_labels == {}:
                    if len(rule.ports) == 0:
                        for namespace in targeted_namespaces:
                            targets[namespace] = 1
                    else:
                        for namespace in targeted_namespaces:
                            for port in rule.ports:
                                targets[self._namespace_port_endpoint(namespace, port, port.protocol, clusterwide)] = 1
                elif len(rule.ports) == 0:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=False, clusterwide=clusterwide)
                else:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=True, ports=rule.ports, clusterwide=clusterwide)
                    self._ensure_container_port_columns(targeted_namespaces, rule.target_labels, rule.ports, clusterwide)
            else:
                if allow_all:
                    for namespace_name in self.all_namespace_names():
                        sources[namespace_name] = 1
                else:
                    for namespace in targeted_namespaces:
                        if rule.target_labels == {}:
                            sources[namespace] = 1
                        else:
                            for workload in self.workloads.get(namespace, []):
                                if self._labels_match(workload.labels, rule.target_labels):
                                    sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1

                ingress_target_namespaces = self._ingress_target_namespaces(policy)
                if policy.source_labels == {}:
                    if len(rule.ports) == 0:
                        for namespace_name in ingress_target_namespaces:
                            targets[namespace_name] = 1
                    else:
                        for namespace_name in ingress_target_namespaces:
                            for port in rule.ports:
                                targets[self._namespace_port_endpoint(namespace_name, port, port.protocol, clusterwide)] = 1
                elif len(rule.ports) == 0:
                    self._add_label_targets(
                        targets, ingress_target_namespaces, policy.source_labels, with_ports=False, clusterwide=clusterwide,
                    )
                else:
                    self._add_label_targets(
                        targets, ingress_target_namespaces, policy.source_labels,
                        with_ports=True, ports=rule.ports, clusterwide=clusterwide,
                    )

            self._ensure_endpoint_columns(targets.keys())
            if rule.is_deny:
                self.fill_matrix_deny(sources, targets, rule.policy_type, policy.namespace)
            else:
                self.fill_matrix(sources, targets, rule.policy_type, policy.namespace, allow_all=allow_all)

    def _ensure_container_port_columns(self, namespaces, label_selector, ports, clusterwide=False):
        for namespace in namespaces:
            for workload in self.workloads.get(namespace, []):
                if not self._labels_match(workload.labels, label_selector):
                    continue
                for container in workload.containers:
                    if container.port == "":
                        continue
                    for port in ports:
                        column = self._encode_endpoint(
                            self._endpoint_namespace(namespace, clusterwide), workload.name, container.port, port.protocol)
                        if column not in self.egress_matrix.columns:
                            self.egress_matrix[column] = 1
                        if column not in self.ingress_matrix.columns:
                            self.ingress_matrix[column] = 1

    def _ensure_endpoint_columns(self, endpoints):
        for endpoint in endpoints:
            if endpoint in self.all_namespace_names():
                continue
            if endpoint not in self.egress_matrix.columns:
                self.egress_matrix[endpoint] = 1
            if endpoint not in self.ingress_matrix.columns:
                self.ingress_matrix[endpoint] = 1

    def _add_label_targets(self, targets, namespaces, label_selector, with_ports=False, ports=None, clusterwide=False):
        for namespace in namespaces:
            endpoint_namespace = self._endpoint_namespace(namespace, clusterwide)
            for workload in self.workloads.get(namespace, []):
                if self._labels_match(workload.labels, label_selector):
                    if with_ports:
                        for port in ports:
                            targets[self._encode_endpoint(endpoint_namespace, workload.name, port.portNumber, port.protocol)] = 1
                    else:
                        targets[self._workload_endpoint(namespace, workload.name, clusterwide)] = 1

            for service in self.services.get(namespace, []):
                if self._labels_match(service.selector, label_selector):
                    if with_ports:
                        for port in service.ports:
                            for rule_port in ports:
                                if port.port == rule_port.portNumber:
                                    targets[self._service_endpoint(
                                        namespace, service.identity, rule_port.portNumber, rule_port.protocol, clusterwide)] = 1
                    else:
                        targets[self._service_endpoint(namespace, service.identity, clusterwide=clusterwide)] = 1

    def _ensure_ingress_row(self, source):
        if source not in self.ingress_matrix.index:
            self.ingress_matrix.loc[source] = 1
            for col in self.ingress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.ingress_matrix.at[source, col] = 0

    def _ensure_egress_row(self, source):
        if source not in self.egress_matrix.index:
            self.egress_matrix.loc[source] = 1
            for col in self.egress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.egress_matrix.at[source, col] = 0

    def _ensure_egress_column(self, target):
        if target not in self.egress_matrix.columns:
            self.egress_matrix[target] = 1
            for row in self.egress_matrix.index:
                if row in self.is_policy_applied and self.is_policy_applied[row] in (2, 3):
                    self.egress_matrix.at[row, target] = 0

    def _apply_parent_endpoints(self, endpoint_name, policy_type, restricted_source=None):
        for new_endpoint in self._endpoint_parent_chain(endpoint_name):
            self.update_is_policy_applied(policy_type, new_endpoint)
            if policy_type == "Ingress":
                if new_endpoint not in self.is_policy_applied or self.is_policy_applied[new_endpoint] in (1, 3):
                    if new_endpoint not in self.ingress_matrix.columns:
                        self.ingress_matrix[new_endpoint] = 1
                    self.ingress_matrix[new_endpoint] = 0
                self._ensure_egress_column(new_endpoint)
                if new_endpoint not in self.is_policy_applied:
                    self.is_policy_applied[new_endpoint] = 1
                elif self.is_policy_applied[new_endpoint] == 2:
                    self.is_policy_applied[new_endpoint] = 3
            else:
                if new_endpoint not in self.egress_matrix.columns:
                    self.egress_matrix[new_endpoint] = 0
                    for row in self.egress_matrix.index:
                        if row == restricted_source:
                            continue
                        if row not in self.is_policy_applied or self.is_policy_applied[row] == 1:
                            self.egress_matrix.at[row, new_endpoint] = 1
                elif restricted_source is not None:
                    self.egress_matrix.at[restricted_source, new_endpoint] = 0
                if new_endpoint not in self.ingress_matrix.columns:
                    self.ingress_matrix[new_endpoint] = 1

    def fill_matrix(self, source_workloads, target_endpoints, policy_type, policy_namespace, allow_all=False):
        if policy_type == "Ingress":
            if len(target_endpoints) == 0:
                if policy_namespace not in self.ingress_matrix.columns:
                    self.ingress_matrix[policy_namespace] = 1
                self.ingress_matrix[policy_namespace] = 0
                if policy_namespace not in self.is_policy_applied:
                    self.is_policy_applied[policy_namespace] = 1
                elif self.is_policy_applied[policy_namespace] == 2:
                    self.is_policy_applied[policy_namespace] = 3
                return

            for target in target_endpoints:
                if target not in self.ingress_matrix.columns:
                    self.ingress_matrix[target] = 1
                    for row in self.ingress_matrix.index:
                        if row in self.is_policy_applied and self.is_policy_applied[row] in (2, 3):
                            self.ingress_matrix.at[row, target] = 0

                if allow_all:
                    self.ingress_matrix[target] = 1
                else:
                    self.ingress_matrix[target] = 0

                self._ensure_egress_column(target)

                for source in source_workloads:
                    self._ensure_ingress_row(source)
                    self._ensure_egress_row(source)
                    self.ingress_matrix.at[source, target] = 1
                    self.ingress_matrix.loc[source] = self.ingress_matrix.loc[source].fillna(1)

                self._apply_parent_endpoints(target, policy_type)
                self.update_is_policy_applied(policy_type, target)
        else:
            for source in source_workloads:
                self._ensure_egress_row(source)
                self._ensure_ingress_row(source)

                if len(target_endpoints) == 0:
                    self.egress_matrix.loc[source] = 0
                    self.update_is_policy_applied(policy_type, source)
                    continue

                if allow_all:
                    self.egress_matrix.loc[source] = 1
                    self.update_is_policy_applied(policy_type, source)
                    continue

                if source not in self.is_policy_applied or self.is_policy_applied[source] == 1:
                    self.egress_matrix.loc[source] = 0

                for target in target_endpoints:
                    self._apply_parent_endpoints(target, policy_type, restricted_source=source)

                    if target not in self.egress_matrix.columns:
                        self.egress_matrix[target] = 1
                        for row in self.egress_matrix.index:
                            if row in self.is_policy_applied and self.is_policy_applied[row] in (2, 3):
                                self.egress_matrix.at[row, target] = 0
                    self.egress_matrix.at[source, target] = 1
                    self.egress_matrix[target] = self.egress_matrix[target].fillna(1)
                    self.egress_matrix.loc[source] = self.egress_matrix.loc[source].fillna(0)

                    if target not in self.ingress_matrix.columns:
                        self.ingress_matrix[target] = 1
                    self.ingress_matrix.at[source, target] = 1

                self.update_is_policy_applied(policy_type, source)

    def fill_matrix_deny(self, source_workloads, target_endpoints, policy_type, policy_namespace):
        if policy_type == "Ingress":
            if len(target_endpoints) == 0:
                if policy_namespace not in self.ingress_matrix.columns:
                    self.ingress_matrix[policy_namespace] = 1
                self.ingress_matrix[policy_namespace] = 0
                return

            for target in target_endpoints:
                if target not in self.ingress_matrix.columns:
                    self.ingress_matrix[target] = 1
                for source in source_workloads:
                    self._ensure_ingress_row(source)
                    self._ensure_egress_row(source)
                    self.ingress_matrix.at[source, target] = 0
        else:
            for source in source_workloads:
                self._ensure_egress_row(source)
                self._ensure_ingress_row(source)
                if len(target_endpoints) == 0:
                    self.egress_matrix.loc[source] = 0
                    continue
                for target in target_endpoints:
                    if target not in self.egress_matrix.columns:
                        self.egress_matrix[target] = 1
                    self.egress_matrix.at[source, target] = 0

    def update_is_policy_applied(self, policy_type, component):
        if policy_type == "Ingress":
            if component in self.is_policy_applied:
                if self.is_policy_applied[component] == 2:
                    self.is_policy_applied[component] = 3
            else:
                self.is_policy_applied[component] = 1
        else:
            if component in self.is_policy_applied:
                if self.is_policy_applied[component] == 1:
                    self.is_policy_applied[component] = 3
            else:
                self.is_policy_applied[component] = 2

    def intersect_egress_and_igress(self):
        self.reachability_matrix = self.egress_matrix * self.ingress_matrix

    def print_reachability_table(self):
        if self.reachability_matrix.empty:
            print("Empty reachability matrix.")
            return
        print(self.reachability_matrix)


if __name__ == "__main__":
    application_folder_path = "./application/aks-store-demo"
    policy_folder_path = "./network_policies/network.yaml"
    if len(sys.argv) > 2:
        application_folder_path = sys.argv[1]
        policy_folder_path = sys.argv[2]
    elif len(sys.argv) > 1:
        application_folder_path = sys.argv[1]

    container_discoverer = ContainerDiscoverer(application_folder_path)
    policy_parser = PolicyParser(policy_folder_path)

    reachability_creator = ReachabilityCreator(
        container_discoverer.services,
        container_discoverer.workloads,
        container_discoverer.namespaces,
        policy_parser.network_policies,
    )

    reachability_matrix = reachability_creator.create_reachability_matrix()
    reachability_creator.print_reachability_table()
