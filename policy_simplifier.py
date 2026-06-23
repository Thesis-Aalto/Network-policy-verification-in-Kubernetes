from container_discoverer import ContainerDiscoverer
from policy_parser import PolicyParser
from reachability_creator import ReachabilityCreator, WILDCARD

import os
import sys


class PolicySimplifier:
    """
    Compare two network policy sets against the same application topology.

    Pairs whose source and destination both appear in both matrices are compared
    using the stored matrix values. Any pair involving a row or column that exists
    in only one matrix is compared with query_reachability on both policy sets.
    """

    def __init__(self, application_path, policies_a_path, policies_b_path):
        self.application_path = application_path
        self.policies_a_path = policies_a_path
        self.policies_b_path = policies_b_path

        container_discoverer = ContainerDiscoverer(application_path)
        self.services = container_discoverer.services
        self.workloads = container_discoverer.workloads
        self.namespaces = container_discoverer.namespaces

        self.rc_a = ReachabilityCreator(
            self.services,
            self.workloads,
            self.namespaces,
            self._load_policies(policies_a_path),
        )
        self.rc_b = ReachabilityCreator(
            self.services,
            self.workloads,
            self.namespaces,
            self._load_policies(policies_b_path),
        )
        self.matrix_a = self.rc_a.create_reachability_matrix().astype(int)
        self.matrix_b = self.rc_b.create_reachability_matrix().astype(int)

    def _load_policies(self, path):
        policies = []
        if os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.endswith((".yaml", ".yml")):
                    parser = PolicyParser(os.path.join(path, filename))
                    policies.extend(parser.network_policies)
            return policies

        parser = PolicyParser(path)
        return parser.network_policies

    def are_equal(self):
        """Return True when both policy sets produce equivalent reachability."""
        return self.compare()["equal"]

    def compare(self):
        """
        Compare connectivity across the union of both matrices.

        - common_rows x common_cols: compare matrix cell values
        - any pair with a row or column exclusive to one matrix: query both sides
        """
        rows_a = set(self.matrix_a.index)
        rows_b = set(self.matrix_b.index)
        cols_a = set(self.matrix_a.columns)
        cols_b = set(self.matrix_b.columns)

        common_rows = rows_a & rows_b
        common_cols = cols_a & cols_b
        only_rows_a = rows_a - rows_b
        only_rows_b = rows_b - rows_a
        only_cols_a = cols_a - cols_b
        only_cols_b = cols_b - cols_a

        all_rows = rows_a | rows_b
        all_cols = cols_a | cols_b

        differences = []

        for source in all_rows:
            for destination in all_cols:
                if source in common_rows and destination in common_cols:
                    value_a = int(self.matrix_a.loc[source, destination])
                    value_b = int(self.matrix_b.loc[source, destination])
                    method = "matrix"
                else:
                    value_a = self._query_value(self.rc_a, source, destination)
                    value_b = self._query_value(self.rc_b, source, destination)
                    method = "query"

                if value_a is None and value_b is None:
                    continue
                if value_a != value_b:
                    differences.append({
                        "source": source,
                        "destination": destination,
                        "value_a": value_a,
                        "value_b": value_b,
                        "method": method,
                    })

        return {
            "equal": len(differences) == 0,
            "differences": differences,
            "summary": {
                "common_rows": common_rows,
                "common_cols": common_cols,
                "rows_only_a": only_rows_a,
                "rows_only_b": only_rows_b,
                "cols_only_a": only_cols_a,
                "cols_only_b": only_cols_b,
            },
        }

    def _query_value(self, reachability_creator, source, destination):
        query = self._build_query(source, destination, reachability_creator)
        if query is None:
            return None
        result = reachability_creator.query_reachability(*query)
        if result == "invalid query":
            return None
        return 1 if result["reachable"] else 0

    def _build_query(self, source_endpoint, destination_endpoint, reachability_creator):
        """Convert matrix row/column endpoints into query_reachability arguments."""
        try:
            source_namespace, source_workload, _, _ = reachability_creator._parse_endpoint(source_endpoint)
            dest_namespace, dest_workload, dest_port, dest_protocol = reachability_creator._parse_endpoint(
                destination_endpoint,
            )
        except ValueError:
            return None

        if source_namespace == WILDCARD or dest_namespace == WILDCARD:
            return None

        source_workload = None if source_workload == WILDCARD else source_workload
        dest_workload = None if dest_workload == WILDCARD else dest_workload
        port = self._query_port(dest_port)
        protocol = None if dest_protocol == WILDCARD else dest_protocol

        return source_namespace, dest_namespace, source_workload, dest_workload, port, protocol

    def _query_port(self, port_token):
        if port_token == WILDCARD:
            return None
        if port_token.isdigit():
            return int(port_token)
        if "-" in port_token:
            start, _ = port_token.split("-", 1)
            if start.isdigit():
                return int(start)
        return None


if __name__ == "__main__":
    application_path = "./application/aks-store-demo"
    policies_a_path = "./network_policies/network-a.yaml"
    policies_b_path = "./network_policies/network-b.yaml"

    if len(sys.argv) > 3:
        application_path = sys.argv[1]
        policies_a_path = sys.argv[2]
        policies_b_path = sys.argv[3]
    elif len(sys.argv) > 2:
        policies_a_path = sys.argv[1]
        policies_b_path = sys.argv[2]

    simplifier = PolicySimplifier(application_path, policies_a_path, policies_b_path)
    result = simplifier.compare()
    print(f"Equal: {result['equal']}")
    print(f"Summary: {result['summary']}")
    if not result["equal"]:
        print(f"Differences: {len(result['differences'])}")
        for diff in result["differences"][:10]:
            print(diff)
