from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer

import sys
import pandas as pd

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 2000)

###TODO: Add internet as both row and column
###TODO: Create NetworkPolicyRecommender to recommend network policies
class ReachabilityCreator():
    """
    Builds a reachability matrix from Kubernetes network policies and cluster topology.

    Rows are traffic sources and columns are destinations. Values are 1 (allowed) or 0 (denied).
    Endpoints can be namespaces (e.g. backend-ns) or more specific labels such as
    backend-ns_order-service or backend-ns_makeline-service_3001_TCP.

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
        # Tracks which endpoints already have a policy applied:
        # 1 = ingress only, 2 = egress only, 3 = both
        self.is_policy_applied = {}
        self.reachability_matrix = pd.DataFrame()

    def create_reachability_matrix(self):
        for policy in self.network_policies:
            self.apply_network_policy(policy)
        self.intersect_egress_and_igress()
        return self.reachability_matrix

    def initialize_matrix(self):
        # Default cluster state: every namespace can reach every namespace.
        new_matrix = pd.DataFrame()
        for source_namespace in self.namespaces:
            for target_namespace in self.namespaces:
                new_matrix.at[source_namespace.name, target_namespace.name] = 1
        return new_matrix

    def all_namespace_names(self):
        return [namespace.name for namespace in self.namespaces]

    def is_allow_all_rule(self, rule):
        # An empty ingress/egress rule ({}) explicitly allows all peers.
        return rule.target_labels == {} and rule.namespace_label == {} and len(rule.ports) == 0

    def _labels_match(self, labels, selector):
        return all(key in labels and labels[key] == value for key, value in selector.items())

    def apply_network_policy(self, policy):
        # policyTypes with no ingress/egress rules means deny-all for selected pods.
        if len(policy.rules) == 0:
            sources = {}
            if policy.source_labels == {}:
                sources[policy.namespace] = 1
            else:
                for workload in self.workloads.get(policy.namespace, []):
                    if self._labels_match(workload.labels, policy.source_labels):
                        sources[f"{workload.namespace}_{workload.name}"] = 1
            for policy_type in policy.policy_types:
                self.fill_matrix(sources, {}, policy_type, policy.namespace)
            return

        for rule in policy.rules:
            sources = {}
            targets = {}
            allow_all = self.is_allow_all_rule(rule)

            if rule.namespace_label:
                targeted_namespaces = [
                    namespace.name
                    for namespace in self.namespaces
                    if self._labels_match(namespace.labels, rule.namespace_label)
                ]
            else:
                # podSelector without namespaceSelector is scoped to the policy namespace.
                targeted_namespaces = [policy.namespace]

            if rule.policy_type == "Egress":
                if policy.source_labels == {}:
                    sources[policy.namespace] = 1
                else:
                    for workload in self.workloads.get(policy.namespace, []):
                        if self._labels_match(workload.labels, policy.source_labels):
                            sources[f"{workload.namespace}_{workload.name}"] = 1

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
                                targets[f"{namespace}_{port.portNumber}_{port.protocol}"] = 1
                elif len(rule.ports) == 0:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=False, policy_namespace=policy.namespace)
                else:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=True, ports=rule.ports, policy_namespace=policy.namespace)
                    # Also expose real container listen ports for port-mismatch scenarios.
                    self._ensure_container_port_columns(targeted_namespaces, rule.target_labels, rule.ports)
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
                                    sources[f"{workload.namespace}_{workload.name}"] = 1

                # For ingress, policy.source_labels (podSelector) defines the protected targets.
                if policy.source_labels == {}:
                    if len(rule.ports) == 0:
                        targets[policy.namespace] = 1
                    else:
                        for port in rule.ports:
                            targets[f"{policy.namespace}_{port.portNumber}_{port.protocol}"] = 1
                elif len(rule.ports) == 0:
                    self._add_label_targets(targets, [policy.namespace], policy.source_labels, with_ports=False, policy_namespace=policy.namespace)
                else:
                    self._add_label_targets(targets, [policy.namespace], policy.source_labels, with_ports=True, ports=rule.ports, policy_namespace=policy.namespace)

            # Pod/workload endpoints must exist in both matrices before multiplication.
            self._ensure_endpoint_columns(sources.keys())
            if rule.policy_type == "Egress" and policy.source_labels != {}:
                for namespace, workloads in self.workloads.items():
                    for workload in workloads:
                        self._ensure_endpoint_columns([f"{namespace}_{workload.name}"])
            self.fill_matrix(sources, targets, rule.policy_type, policy.namespace, allow_all=allow_all)

    def _ensure_container_port_columns(self, namespaces, label_selector, ports):
        """
        Add columns for actual container ports (e.g. ratings-v1_9080_TCP) even when the
        policy references a different port. Namespace-level rows stay allowed on those columns;
        restricted pod rows are handled later in fill_matrix.
        """
        for namespace in namespaces:
            for workload in self.workloads.get(namespace, []):
                if not self._labels_match(workload.labels, label_selector):
                    continue
                for container in workload.containers:
                    if container.port == "":
                        continue
                    for port in ports:
                        column = f"{namespace}_{workload.name}_{container.port}_{port.protocol}"
                        if column not in self.egress_matrix.columns:
                            self.egress_matrix[column] = 1
                        if column not in self.ingress_matrix.columns:
                            self.ingress_matrix[column] = 1

    def _ensure_endpoint_columns(self, endpoints):
        """Add workload-level destination columns defaulting to allow-all."""
        for endpoint in endpoints:
            if endpoint in self.all_namespace_names():
                continue
            if endpoint not in self.egress_matrix.columns:
                self.egress_matrix[endpoint] = 1
            if endpoint not in self.ingress_matrix.columns:
                self.ingress_matrix[endpoint] = 1

    def _add_label_targets(self, targets, namespaces, label_selector, with_ports=False, ports=None, policy_namespace=None):
        for namespace in namespaces:
            for workload in self.workloads.get(namespace, []):
                if self._labels_match(workload.labels, label_selector):
                    if with_ports:
                        # Use the port declared in the policy, even on port-mismatch cases.
                        for port in ports:
                            targets[f"{namespace}_{workload.name}_{port.portNumber}_{port.protocol}"] = 1
                    else:
                        targets[f"{namespace}_{workload.name}"] = 1

            # Service targets are only included for same-namespace egress/ingress rules.
            include_services = policy_namespace is None or namespace == policy_namespace
            if include_services:
                for service in self.services.get(namespace, []):
                    if self._labels_match(service.selector, label_selector):
                        if with_ports:
                            for port in service.ports:
                                for rule_port in ports:
                                    if port.port == rule_port.portNumber:
                                        targets[f"{namespace}_{service.identity}_{rule_port.portNumber}_{rule_port.protocol}"] = 1
                        else:
                            targets[f"{namespace}_{service.identity}"] = 1

    def _ensure_ingress_row(self, source):
        """Create a missing source row and respect ingress restrictions on existing columns."""
        if source not in self.ingress_matrix.index:
            self.ingress_matrix.loc[source] = 1
            for col in self.ingress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.ingress_matrix.at[source, col] = 0

    def _ensure_egress_row(self, source):
        """Create a missing source row and respect egress restrictions on existing columns."""
        if source not in self.egress_matrix.index:
            self.egress_matrix.loc[source] = 1
            for col in self.egress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.egress_matrix.at[source, col] = 0

    def _ensure_egress_column(self, target):
        """Create a missing destination column and respect egress restrictions on existing rows."""
        if target not in self.egress_matrix.columns:
            self.egress_matrix[target] = 1
            for row in self.egress_matrix.index:
                if row in self.is_policy_applied and self.is_policy_applied[row] in (2, 3):
                    self.egress_matrix.at[row, target] = 0

    def fill_matrix(self, source_workloads, target_endpoints, policy_type, policy_namespace, allow_all=False):
        if policy_type == "Ingress":
            if len(target_endpoints) == 0:
                # Deny-all ingress: block every source from reaching this namespace.
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
                    # Kubernetes default-deny for protected targets: clear the column, then allow listed sources.
                    self.ingress_matrix[target] = 0

                self._ensure_egress_column(target)

                for source in source_workloads:
                    self._ensure_ingress_row(source)
                    self._ensure_egress_row(source)
                    self.ingress_matrix.at[source, target] = 1
                    self.ingress_matrix.loc[source] = self.ingress_matrix.loc[source].fillna(1)

                # Build broader parent endpoints from port-specific targets
                # (e.g. backend-ns_svc_3001_TCP -> backend-ns_svc_3001 -> backend-ns_svc).
                target_components = target.split("_")
                while len(target_components) > 2:
                    target_components.pop()
                    new_endpoint = "_".join(target_components)
                    self.update_is_policy_applied(policy_type, new_endpoint)
                    if new_endpoint not in self.is_policy_applied or self.is_policy_applied[new_endpoint] in (1, 3):
                        if new_endpoint not in self.ingress_matrix.columns:
                            self.ingress_matrix[new_endpoint] = 1
                        self.ingress_matrix[new_endpoint] = 0

                    self._ensure_egress_column(new_endpoint)

                    if new_endpoint not in self.is_policy_applied:
                        self.is_policy_applied[new_endpoint] = 1
                    elif self.is_policy_applied[new_endpoint] == 2:
                        self.is_policy_applied[new_endpoint] = 3

                self.update_is_policy_applied(policy_type, target)
        else:
            for source in source_workloads:
                self._ensure_egress_row(source)
                self._ensure_ingress_row(source)

                if len(target_endpoints) == 0:
                    # Deny-all egress: the source cannot reach any destination.
                    self.egress_matrix.loc[source] = 0
                    self.update_is_policy_applied(policy_type, source)
                    continue

                if allow_all:
                    self.egress_matrix.loc[source] = 1
                    self.update_is_policy_applied(policy_type, source)
                    continue

                # Default-deny egress for this source, then allow only listed targets.
                if source not in self.is_policy_applied or self.is_policy_applied[source] == 1:
                    self.egress_matrix.loc[source] = 0

                for target in target_endpoints:
                    target_components = target.split("_")
                    while len(target_components) > 2:
                        target_components.pop()
                        new_endpoint = "_".join(target_components)
                        self.update_is_policy_applied(policy_type, new_endpoint)
                        if new_endpoint not in self.egress_matrix.columns:
                            self.egress_matrix[new_endpoint] = 0
                            for row in self.egress_matrix.index:
                                # Do not reopen access for the restricted source on parent endpoints.
                                if row == source:
                                    continue
                                if row not in self.is_policy_applied or self.is_policy_applied[row] == 1:
                                    self.egress_matrix.at[row, new_endpoint] = 1
                        if new_endpoint not in self.ingress_matrix.columns:
                            self.ingress_matrix[new_endpoint] = 1

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
        # Traffic is allowed only when both egress and ingress permit it.
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

    workloads = container_discoverer.workloads
    services = container_discoverer.services
    namespaces = container_discoverer.namespaces
    reachability_creator = ReachabilityCreator(services, workloads, namespaces, policy_parser.network_policies)

    reachability_matrix = reachability_creator.create_reachability_matrix()
    reachability_creator.print_reachability_table()
