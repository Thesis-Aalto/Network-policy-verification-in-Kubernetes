from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer

import ipaddress
import sys
import pandas as pd

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 2000)

WILDCARD = "*"
KNOWN_PROTOCOLS = frozenset({"TCP", "UDP", "SCTP"})
ENDPOINT_SEP = "_"
QUERY_TIER_PRIORITY = ("cilium_deny", "policy_allow", "policy_deny", "default")
QUERY_DENY_TIERS = frozenset({"cilium_deny", "policy_deny"})


class ReachabilityCreator():
    """
    Builds a reachability matrix from Kubernetes network policies and cluster topology.

    Rows are traffic sources and columns are destinations. Values are 1 (allowed) or 0 (denied).
    Endpoints use fixed format namespace_workload_port_protocol with '*' wildcards, e.g.
    backend-ns_makeline-service_*_* or database-ns_*_5672_TCP. Namespace-level endpoints use
    namespace_*_*_*. External ipBlocks use the CIDR in the workload slot, e.g. backend-ns_10.0.0.0/24_*_*.

    Ingress and egress are tracked separately, then combined with element-wise multiplication:
    reachability = egress_matrix * ingress_matrix

    is_policy_applied tracks endpoints affected by policies:
      1 = ingress (destination/column), 2 = egress (source/row), 3 = both
    engine_deny_cells maps (source, destination) to "cilium" for deny priority.
    """

    def __init__(self, services, workloads, namespaces, network_policies):
        """Initialize matrices and policy-tracking state from cluster topology and policies."""
        self.services = services
        self.workloads = workloads
        self.namespaces = namespaces
        self.network_policies = network_policies

        self.ingress_matrix = self.initialize_matrix()
        self.egress_matrix = self.initialize_matrix()
        self.is_policy_applied = {}
        self.engine_deny_cells = {}
        self.reachability_matrix = pd.DataFrame()

    def create_reachability_matrix(self):
        """Apply all policies in three phases (policy-deny, allow, CNI-deny) and build the final matrix."""
        for policy in self.network_policies:
            if len(policy.rules) == 0:
                self.apply_network_policy(policy, phase="policy_deny")
        for policy in self.network_policies:
            self.apply_network_policy(policy, phase="allow")
        for policy in self.network_policies:
            self.apply_network_policy(policy, phase="cni_deny")
        self.intersect_egress_and_igress()
        return self.reachability_matrix

    def initialize_matrix(self):
        """Create a namespace-to-namespace matrix with all cells set to allowed (1)."""
        new_matrix = pd.DataFrame()
        for source_namespace in self.namespaces:
            for target_namespace in self.namespaces:
                source = self._namespace_endpoint(source_namespace.name)
                target = self._namespace_endpoint(target_namespace.name)
                new_matrix.at[source, target] = 1
        return new_matrix

    def all_namespace_names(self):
        """Return the list of all namespace names in the cluster."""
        return [namespace.name for namespace in self.namespaces]

    def is_allow_all_rule(self, rule):
        """Return True when a rule has no selectors, no ipBlock, and no ports (matches everything)."""
        return (
            rule.target_labels == {}
            and rule.namespace_label == {}
            and rule.ip_block_cidr is None
            and len(rule.ports) == 0
        )

    def _is_cidr_identity(self, identity):
        """Return True when an endpoint identity string is a CIDR range."""
        return identity != WILDCARD and "/" in identity

    def _is_ip_address(self, identity):
        """Return True when an identity string is a specific IP address."""
        if identity is None or identity == WILDCARD or self._is_cidr_identity(identity):
            return False
        try:
            ipaddress.ip_address(identity)
            return True
        except ValueError:
            return False

    def _identity_matches(self, query_identity, endpoint_identity):
        """Match pod/CIDR names exactly, or a specific IP against a CIDR endpoint."""
        if endpoint_identity == WILDCARD:
            return True
        if query_identity == endpoint_identity:
            return True
        if self._is_ip_address(query_identity) and self._is_cidr_identity(endpoint_identity):
            try:
                return ipaddress.ip_address(query_identity) in ipaddress.ip_network(
                    endpoint_identity, strict=False,
                )
            except ValueError:
                return False
        return False

    def _labels_match(self, labels, selector):
        """Return True when every key/value in selector is present and equal in labels."""
        return all(key in labels and labels[key] == value for key, value in selector.items())

    def _ingress_target_namespaces(self, policy):
        """Return namespaces whose pods are protected by an ingress policy."""
        if policy.is_clusterwide:
            return self.all_namespace_names()
        return [policy.namespace]

    def _match_namespace(self, endpoint):
        """Extract the namespace prefix from an endpoint string (longest matching namespace name)."""
        if endpoint == WILDCARD or endpoint.startswith(f"{WILDCARD}{ENDPOINT_SEP}"):
            return WILDCARD
        namespace_names = self.all_namespace_names()
        matches = [
            name for name in namespace_names
            if endpoint.startswith(f"{name}{ENDPOINT_SEP}")
        ]
        if not matches:
            raise ValueError(f"Could not parse namespace from endpoint: {endpoint}")
        return max(matches, key=len)

    def _endpoint_namespace(self, namespace, clusterwide=False):
        """Return '*' for clusterwide policies, otherwise the real namespace name."""
        return WILDCARD if clusterwide else namespace

    def _namespace_endpoint(self, namespace):
        """Encode a namespace-level endpoint: namespace_*_*_*."""
        return self._encode_endpoint(namespace)

    def _encode_endpoint(self, namespace, workload=WILDCARD, port=WILDCARD, protocol=WILDCARD):
        """Build an endpoint string from namespace, workload, port, and protocol components."""
        workload = str(workload) if workload != WILDCARD else WILDCARD
        port = str(port) if port != WILDCARD else WILDCARD
        return ENDPOINT_SEP.join([namespace, workload, port, protocol])

    def _parse_endpoint(self, endpoint):
        """Split an endpoint string into (namespace, workload, port, protocol) tuple."""
        namespace = self._match_namespace(endpoint)
        remainder = endpoint[len(namespace) + len(ENDPOINT_SEP):]
        parts = remainder.split(ENDPOINT_SEP) if remainder else []

        protocol = WILDCARD
        port = WILDCARD
        if parts and (parts[-1] in KNOWN_PROTOCOLS or parts[-1] == WILDCARD):
            protocol = parts.pop()
        if parts and self._is_port_token(parts[-1]):
            port = parts.pop()

        workload = WILDCARD
        if parts:
            workload = ENDPOINT_SEP.join(parts)
            if workload == "":
                workload = WILDCARD

        return namespace, workload, port, protocol

    def _is_port_token(self, token):
        """Return True when a token is a port number or port range."""
        if token == WILDCARD:
            return True
        if token.isdigit():
            return True
        if "-" in token:
            start, end = token.split("-", 1)
            return start.isdigit() and end.isdigit()
        return False

    def _endpoint_parent_chain(self, endpoint_name):
        """
        Return broader parent endpoints by wildcarding protocol, port, then workload.
        Stops before namespace_*_*_* when the original endpoint had a workload (pod selector).
        """
        ns, wl, pt, pr = self._parse_endpoint(endpoint_name)
        had_identity = wl != WILDCARD
        parents = []
        while True:
            if pr != WILDCARD:
                pr = WILDCARD
            elif pt != WILDCARD:
                pt, pr = WILDCARD, WILDCARD
            elif wl != WILDCARD:
                wl, pt, pr = WILDCARD, WILDCARD, WILDCARD
            else:
                break

            collapse = wl == WILDCARD and pt == WILDCARD and pr == WILDCARD
            if collapse and (ns == WILDCARD or had_identity):
                break
            parents.append(self._encode_endpoint(ns, wl, pt, pr))
            if collapse:
                break
        return parents

    def _workload_endpoint(self, namespace, workload_name, clusterwide=False):
        """Encode a workload-level endpoint: namespace_workload_*_*."""
        return self._encode_endpoint(self._endpoint_namespace(namespace, clusterwide), workload_name)

    def _ipblock_endpoint(self, namespace, cidr, port=WILDCARD, protocol=WILDCARD, clusterwide=False):
        """Encode an ipBlock endpoint: namespace_cidr_port_protocol."""
        return self._encode_endpoint(self._endpoint_namespace(namespace, clusterwide), cidr, port, protocol)

    def _add_ipblock_endpoints(self, endpoints, namespaces, cidr, ports, clusterwide=False):
        """Add ipBlock CIDR endpoints to a sources or targets dict."""
        for namespace in namespaces:
            endpoint_namespace = self._endpoint_namespace(namespace, clusterwide)
            if not ports:
                endpoints[self._ipblock_endpoint(endpoint_namespace, cidr)] = 1
            else:
                for port in ports:
                    endpoints[self._ipblock_endpoint(
                        endpoint_namespace, cidr, port.endpoint_token(), port.protocol,
                    )] = 1

    def _service_endpoint(self, namespace, service_identity, port=None, protocol=None, clusterwide=False):
        """Encode a service endpoint, with or without port and protocol."""
        endpoint_namespace = self._endpoint_namespace(namespace, clusterwide)
        if port is None:
            return self._encode_endpoint(endpoint_namespace, service_identity)
        return self._encode_endpoint(endpoint_namespace, service_identity, port, protocol)

    def _namespace_port_endpoint(self, namespace, port, protocol, clusterwide=False):
        """Encode a namespace-level port endpoint: namespace_*_port_protocol."""
        port_token = port.endpoint_token() if hasattr(port, "endpoint_token") else str(port.portNumber)
        return self._encode_endpoint(self._endpoint_namespace(namespace, clusterwide), WILDCARD, port_token, protocol)

    def apply_network_policy(self, policy, phase="allow"):
        """
        Apply one policy in a given phase (allow, policy-deny, or CNI-deny).
        Resolves sources and targets from selectors, then updates ingress/egress matrices.
        """
        clusterwide = policy.is_clusterwide
        if phase == "policy_deny":
            sources = {}
            source_namespaces = self.all_namespace_names() if clusterwide else [policy.namespace]
            if policy.source_labels == {}:
                for namespace_name in source_namespaces:
                    sources[self._namespace_endpoint(namespace_name)] = 1
            else:
                for namespace_name in source_namespaces:
                    for workload in self.workloads.get(namespace_name, []):
                        if self._labels_match(workload.labels, policy.source_labels):
                            sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1
            for policy_type in policy.policy_types:
                self.apply_namespace_policy_deny(sources, policy_type, policy.namespace)
            return

        if len(policy.rules) == 0:
            return

        for rule in policy.rules:
            if phase == "allow" and rule.is_deny:
                continue
            if phase == "cni_deny" and not rule.is_deny:
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
            elif clusterwide:
                targeted_namespaces = self.all_namespace_names()
            else:
                targeted_namespaces = [policy.namespace]

            source_namespaces = self.all_namespace_names() if clusterwide else [policy.namespace]

            if rule.policy_type == "Egress":
                if policy.source_labels == {}:
                    for namespace_name in source_namespaces:
                        sources[self._namespace_endpoint(namespace_name)] = 1
                else:
                    for namespace_name in source_namespaces:
                        for workload in self.workloads.get(namespace_name, []):
                            if self._labels_match(workload.labels, policy.source_labels):
                                sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1

                if allow_all:
                    for namespace_name in self.all_namespace_names():
                        targets[self._namespace_endpoint(namespace_name)] = 1
                elif rule.ip_block_cidr:
                    self._add_ipblock_endpoints(
                        targets, targeted_namespaces, rule.ip_block_cidr, rule.ports, clusterwide,
                    )
                elif rule.target_labels == {}:
                    if len(rule.ports) == 0:
                        for namespace in targeted_namespaces:
                            targets[self._namespace_endpoint(namespace)] = 1
                    else:
                        for namespace in targeted_namespaces:
                            for port in rule.ports:
                                targets[self._namespace_port_endpoint(namespace, port, port.protocol, clusterwide)] = 1
                elif len(rule.ports) == 0:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=False, clusterwide=clusterwide)
                else:
                    self._add_label_targets(targets, targeted_namespaces, rule.target_labels, with_ports=True, ports=rule.ports, clusterwide=clusterwide)
            else:
                if allow_all:
                    for namespace_name in self.all_namespace_names():
                        sources[self._namespace_endpoint(namespace_name)] = 1
                elif rule.ip_block_cidr:
                    self._add_ipblock_endpoints(
                        sources, targeted_namespaces, rule.ip_block_cidr, rule.ports, clusterwide,
                    )
                else:
                    for namespace in targeted_namespaces:
                        if rule.target_labels == {}:
                            sources[self._namespace_endpoint(namespace)] = 1
                        else:
                            for workload in self.workloads.get(namespace, []):
                                if self._labels_match(workload.labels, rule.target_labels):
                                    sources[self._workload_endpoint(workload.namespace, workload.name, clusterwide)] = 1

                ingress_target_namespaces = self._ingress_target_namespaces(policy)
                if policy.source_labels == {}:
                    if len(rule.ports) == 0:
                        for namespace_name in ingress_target_namespaces:
                            targets[self._namespace_endpoint(namespace_name)] = 1
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
                self.fill_matrix_deny(
                    sources, targets, rule.policy_type, policy.namespace, policy=policy,
                )
            else:
                self.fill_matrix(
                    sources, targets, rule.policy_type, policy.namespace, allow_all=allow_all,
                )

    def _ensure_endpoint_columns(self, endpoints):
        """Add missing endpoint columns to both matrices, initialized to allowed (1)."""
        for endpoint in endpoints:
            if self._is_namespace_endpoint(endpoint):
                continue
            if endpoint not in self.egress_matrix.columns:
                self.egress_matrix[endpoint] = 1
            if endpoint not in self.ingress_matrix.columns:
                self.ingress_matrix[endpoint] = 1

    def _add_label_targets(self, targets, namespaces, label_selector, with_ports=False, ports=None, clusterwide=False):
        """Add workload and service endpoints matching a label selector to the targets dict."""
        for namespace in namespaces:
            endpoint_namespace = self._endpoint_namespace(namespace, clusterwide)
            for workload in self.workloads.get(namespace, []):
                if self._labels_match(workload.labels, label_selector):
                    if with_ports:
                        for port in ports:
                            targets[self._encode_endpoint(
                                endpoint_namespace, workload.name, port.endpoint_token(), port.protocol,
                            )] = 1
                    else:
                        targets[self._workload_endpoint(namespace, workload.name, clusterwide)] = 1

            for service in self.services.get(namespace, []):
                if self._labels_match(service.selector, label_selector):
                    if with_ports:
                        for service_port in service.ports:
                            for rule_port in ports:
                                if rule_port.contains(service_port.port):
                                    targets[self._service_endpoint(
                                        namespace, service.identity, rule_port.endpoint_token(), rule_port.protocol, clusterwide,
                                    )] = 1
                    else:
                        targets[self._service_endpoint(namespace, service.identity, clusterwide=clusterwide)] = 1

    def _ensure_ingress_row(self, source):
        """Add a source row to the ingress matrix, blocking ingress-protected columns."""
        if source not in self.ingress_matrix.index:
            self.ingress_matrix.loc[source] = 1
            for col in self.ingress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.ingress_matrix.at[source, col] = 0

    def _ensure_egress_row(self, source):
        """Add a source row to the egress matrix, blocking ingress-protected columns."""
        if source not in self.egress_matrix.index:
            self.egress_matrix.loc[source] = 1
            for col in self.egress_matrix.columns:
                if col in self.is_policy_applied and self.is_policy_applied[col] in (1, 3):
                    self.egress_matrix.at[source, col] = 0

    def _ensure_egress_column(self, target):
        """Add a target column to the egress matrix, blocking egress-restricted rows."""
        if target not in self.egress_matrix.columns:
            self.egress_matrix[target] = 1
            for row in self.egress_matrix.index:
                if row in self.is_policy_applied and self.is_policy_applied[row] in (2, 3):
                    self.egress_matrix.at[row, target] = 0

    def _apply_parent_endpoints(self, endpoint_name, policy_type, restricted_source=None):
        """
        Propagate policy effects to broader parent endpoints (wildcard aggregation).
        For ingress: parent columns are denied unless already covered by a prior rule.
        For egress: restricted source is blocked on parent unless already explicitly allowed.
        """
        for new_endpoint in self._endpoint_parent_chain(endpoint_name):
            parent_has_ingress_rule = (
                policy_type == "Ingress"
                and new_endpoint in self.is_policy_applied
                and self.is_policy_applied[new_endpoint] in (1, 3)
            )
            self.update_is_policy_applied(policy_type, new_endpoint)
            if policy_type == "Ingress":
                if not parent_has_ingress_rule:
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
                    if self.egress_matrix.at[restricted_source, new_endpoint] != 1:
                        self.egress_matrix.at[restricted_source, new_endpoint] = 0
                if new_endpoint not in self.ingress_matrix.columns:
                    self.ingress_matrix[new_endpoint] = 1

    def _mark_engine_deny_cell(self, policy, source, target):
        """Record a Cilium deny cell for query-time priority resolution."""
        if policy is None or not policy.is_cilium:
            return
        self.engine_deny_cells[(source, target)] = "cilium"

    def apply_namespace_policy_deny(self, source_workloads, policy_type, policy_namespace):
        """Apply implicit deny-all at namespace granularity for empty-rule policies."""
        namespace_endpoint = self._namespace_endpoint(policy_namespace)
        if policy_type == "Ingress":
            if namespace_endpoint not in self.ingress_matrix.columns:
                self.ingress_matrix[namespace_endpoint] = 1
            self.ingress_matrix[namespace_endpoint] = 0
            self.update_is_policy_applied(policy_type, namespace_endpoint)
            return

        for source in source_workloads:
            if not self._is_namespace_endpoint(source):
                self._ensure_egress_row(source)
                self._ensure_ingress_row(source)
            self.egress_matrix.loc[source] = 0
            self.update_is_policy_applied(policy_type, source)

    def fill_matrix(self, source_workloads, target_endpoints, policy_type, policy_namespace, allow_all=False):
        """
        Apply an allow rule to the ingress or egress matrix.
        Sets allowed cells to 1, denies everything else in the affected row/column.
        """
        if policy_type == "Ingress":
            if len(target_endpoints) == 0:
                namespace_endpoint = self._namespace_endpoint(policy_namespace)
                if namespace_endpoint not in self.ingress_matrix.columns:
                    self.ingress_matrix[namespace_endpoint] = 1
                self.ingress_matrix[namespace_endpoint] = 0
                self.update_is_policy_applied(policy_type, namespace_endpoint)
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

    def fill_matrix_deny(self, source_workloads, target_endpoints, policy_type, policy_namespace, policy=None):
        """Apply a deny rule (Cilium egressDeny or ingressDeny) to the matrix."""
        if policy_type == "Ingress":
            if len(target_endpoints) == 0:
                namespace_endpoint = self._namespace_endpoint(policy_namespace)
                if namespace_endpoint not in self.ingress_matrix.columns:
                    self.ingress_matrix[namespace_endpoint] = 1
                self.ingress_matrix[namespace_endpoint] = 0
                return

            for target in target_endpoints:
                if target not in self.ingress_matrix.columns:
                    self.ingress_matrix[target] = 1
                for source in source_workloads:
                    self._ensure_ingress_row(source)
                    self._ensure_egress_row(source)
                    self.ingress_matrix.at[source, target] = 0
                    self._mark_engine_deny_cell(policy, source, target)
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
                    self._mark_engine_deny_cell(policy, source, target)

    def update_is_policy_applied(self, policy_type, component):
        """
        Mark an endpoint as policy-affected in is_policy_applied.
        1 = ingress, 2 = egress, 3 = both.
        """
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
        """Combine ingress and egress matrices: reachability = egress * ingress."""
        self.reachability_matrix = self.egress_matrix * self.ingress_matrix

    # Query resolution: match all applicable matrix endpoints, then decide by tier priority.

    def _is_namespace_endpoint(self, endpoint):
        """Return True when endpoint is namespace-level: namespace_*_*_*."""
        ep_ns, ep_wl, ep_pt, ep_pr = self._parse_endpoint(endpoint)
        return ep_wl == WILDCARD and ep_pt == WILDCARD and ep_pr == WILDCARD and ep_ns != WILDCARD

    def _matches_port_protocol(self, ep_port, ep_protocol, port, protocol):
        """Return True when a destination endpoint port/protocol matches the query."""
        if port is None:
            return ep_port == WILDCARD
        if ep_port != WILDCARD:
            if "-" in ep_port:
                start, end = ep_port.split("-", 1)
                if not int(start) <= int(port) <= int(end):
                    return False
            elif ep_port != str(port):
                return False
        if protocol is None:
            return True
        return ep_protocol == protocol or ep_protocol == WILDCARD

    def _matches_endpoint(self, endpoint, namespace, workload=None, port=None, protocol=None, role="destination"):
        """Return True when a matrix row/column matches the query."""
        if self._is_namespace_endpoint(endpoint):
            ep_ns, _, _, _ = self._parse_endpoint(endpoint)
            return ep_ns == namespace

        ep_ns, ep_wl, ep_pt, ep_pr = self._parse_endpoint(endpoint)
        if ep_ns != WILDCARD and ep_ns != namespace:
            return False
        if workload is not None:
            if not self._identity_matches(workload, ep_wl):
                return False
        elif ep_wl != WILDCARD:
            return False

        if role == "source":
            if workload is not None and (
                self._is_cidr_identity(workload)
                or (self._is_ip_address(workload) and self._is_cidr_identity(ep_wl))
            ):
                return True
            return ep_pt == WILDCARD and ep_pr == WILDCARD

        return self._matches_port_protocol(ep_pt, ep_pr, port, protocol)

    def _cell_tier(self, row, col, value):
        """Map a cell to a query tier for QUERY_TIER_PRIORITY resolution."""
        engine = self.engine_deny_cells.get((row, col))
        if engine == "cilium":
            return "cilium_deny"
        if row in self.is_policy_applied:
            return "policy_allow" if value == 1 else "policy_deny"
        if col in self.is_policy_applied:
            return "policy_allow" if value == 1 else "policy_deny"
        return "default"

    def _resolve_by_priority(self, matches):
        """Pick reachable/not reachable from all matching cells using QUERY_TIER_PRIORITY."""
        for tier in QUERY_TIER_PRIORITY:
            tier_matches = [match for match in matches if match["tier"] == tier]
            if not tier_matches:
                continue
            if tier in QUERY_DENY_TIERS:
                for match in tier_matches:
                    if match["value"] == 0:
                        return False, match, tier
                continue
            for match in tier_matches:
                if match["value"] == 1:
                    return True, match, tier
            if tier == "default":
                return False, tier_matches[0], tier
        match = matches[0]
        return match["value"] == 1, match, match["tier"]

    def query_reachability(self, source_namespace, dest_namespace, source_workload=None, dest_workload=None, port=None, protocol=None):
        """
        Match all applicable matrix rows/columns for the query, then resolve by tier priority.
        Returns a result dict, or "invalid query" when nothing matches.
        """
        if self.reachability_matrix.empty:
            return "invalid query"

        source_rows = sorted(
            row for row in self.reachability_matrix.index
            if self._matches_endpoint(row, source_namespace, source_workload, role="source")
        )
        dest_columns = sorted(
            col for col in self.reachability_matrix.columns
            if self._matches_endpoint(
                col, dest_namespace, dest_workload, port, protocol, role="destination",
            )
        )
        if not source_rows or not dest_columns:
            return "invalid query"

        matches = []
        for row in source_rows:
            for col in dest_columns:
                value = int(self.reachability_matrix.at[row, col])
                matches.append({
                    "source": row,
                    "destination": col,
                    "value": value,
                    "tier": self._cell_tier(row, col, value),
                })
        reachable, deciding_match, tier = self._resolve_by_priority(matches)
        return {
            "reachable": reachable,
            "tier": tier,
            "deciding_match": deciding_match,
            "matches": matches,
            "source_rows": source_rows,
            "dest_columns": dest_columns,
        }

    def print_reachability_table(self):
        """Print the final reachability matrix to stdout."""
        if self.reachability_matrix.empty:
            print("Empty reachability matrix.")
            return
        print(self.egress_matrix)
        print(self.ingress_matrix)
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
