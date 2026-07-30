#!/usr/bin/env python3
"""Measure reachability matrix, query, and policy simplifier performance under policy load."""

import argparse
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message="DataFrame is highly fragmented")

from container_discoverer import ContainerDiscoverer
from policy_parser import Policy, PolicyRule, Port
from policy_simplifier import PolicySimplifier
from reachability_creator import ReachabilityCreator

TESTING_DIR = Path(__file__).resolve().parent
APPLICATION_ROOT = TESTING_DIR / "application"
DEFAULT_POLICY_COUNTS = (10, 25, 50, 100, 1000)
DEFAULT_QUERY_COUNT = 1000
DEFAULT_MATRIX_RUNS = 3

TESTBEDS = {
    "aks-store-demo": {
        "application": APPLICATION_ROOT / "aks-store-demo",
        "base_port": 3000,
        "workloads": [
            ("database-ns", "mongodb"),
            ("database-ns", "rabbitmq"),
            ("backend-ns", "order-service"),
            ("backend-ns", "makeline-service"),
            ("backend-ns", "product-service"),
            ("frontend-ns", "store-front"),
            ("frontend-ns", "store-admin"),
            ("frontend-ns", "virtual-customer"),
        ],
        "query_cases": [
            {
                "name": "pod_to_pod_with_port",
                "description": "Specific source workload, destination workload, port, and protocol",
                "source_namespace": "backend-ns",
                "dest_namespace": "backend-ns",
                "source_workload": "order-service",
                "dest_workload": "makeline-service",
                "port": 3001,
                "protocol": "TCP",
            },
            {
                "name": "pod_to_pod_without_port",
                "description": "Specific source and destination workloads without port filter",
                "source_namespace": "backend-ns",
                "dest_namespace": "backend-ns",
                "source_workload": "order-service",
                "dest_workload": "makeline-service",
            },
            {
                "name": "cross_namespace_with_port",
                "description": "Cross-namespace query with workload and port",
                "source_namespace": "backend-ns",
                "dest_namespace": "database-ns",
                "source_workload": "order-service",
                "dest_workload": "mongodb",
                "port": 27017,
                "protocol": "TCP",
            },
            {
                "name": "namespace_to_namespace",
                "description": "Namespace-level lookup without workload or port",
                "source_namespace": "frontend-ns",
                "dest_namespace": "backend-ns",
            },
            {
                "name": "namespace_to_workload",
                "description": "Namespace source with specific destination workload",
                "source_namespace": "backend-ns",
                "dest_namespace": "database-ns",
                "dest_workload": "rabbitmq",
                "port": 5672,
                "protocol": "TCP",
            },
        ],
    },
    "istio-bookinfo": {
        "application": APPLICATION_ROOT / "istio-bookinfo",
        "base_port": 9080,
        "workloads": [
            ("bookinfo-data-ns", "ratings"),
            ("bookinfo-services-ns", "details"),
            ("bookinfo-services-ns", "reviews"),
            ("bookinfo-frontend-ns", "productpage"),
        ],
        "query_cases": [
            {
                "name": "pod_to_pod_with_port",
                "description": "Specific source workload, destination workload, port, and protocol",
                "source_namespace": "bookinfo-services-ns",
                "dest_namespace": "bookinfo-services-ns",
                "source_workload": "reviews-v1",
                "dest_workload": "details-v1",
                "port": 9080,
                "protocol": "TCP",
            },
            {
                "name": "pod_to_pod_without_port",
                "description": "Specific source and destination workloads without port filter",
                "source_namespace": "bookinfo-services-ns",
                "dest_namespace": "bookinfo-services-ns",
                "source_workload": "reviews-v1",
                "dest_workload": "details-v1",
            },
            {
                "name": "cross_namespace_with_port",
                "description": "Cross-namespace query with workload and port",
                "source_namespace": "bookinfo-services-ns",
                "dest_namespace": "bookinfo-data-ns",
                "source_workload": "reviews-v1",
                "dest_workload": "ratings-v1",
                "port": 9080,
                "protocol": "TCP",
            },
            {
                "name": "namespace_to_namespace",
                "description": "Namespace-level lookup without workload or port",
                "source_namespace": "bookinfo-frontend-ns",
                "dest_namespace": "bookinfo-services-ns",
            },
            {
                "name": "namespace_to_workload",
                "description": "Namespace source with specific destination workload",
                "source_namespace": "bookinfo-services-ns",
                "dest_namespace": "bookinfo-data-ns",
                "dest_workload": "ratings-v1",
                "port": 9080,
                "protocol": "TCP",
            },
        ],
    },
}


def generate_policies(count, workloads, base_port, offset=0):
    """Build synthetic ingress/egress policies for performance testing."""
    policies = []
    workload_count = len(workloads)
    for index in range(count):
        policy_index = index + offset
        namespace, app = workloads[policy_index % workload_count]
        _, peer_app = workloads[(policy_index * 3 + 1) % workload_count]
        policy_type = "Ingress" if policy_index % 2 == 0 else "Egress"
        ports = [Port(base_port + (policy_index % 100), "TCP")] if policy_index % 4 == 0 else []
        rule = PolicyRule(policy_type, {"app": peer_app}, None, ports)
        policies.append(
            Policy(
                name=f"perf-policy-{policy_index}",
                namespace=namespace,
                source_labels={"app": app},
                rules=[rule],
                policy_types=[policy_type],
            )
        )
    return policies


def average_seconds(samples):
    return statistics.mean(samples)


def format_ms(seconds):
    return f"{seconds * 1000:.2f} ms"


def benchmark_matrix_creation(services, workloads, namespaces, policies, runs):
    timings = []
    matrix_stats = None
    for _ in range(runs):
        reachability_creator = ReachabilityCreator(services, workloads, namespaces, policies)
        start = time.perf_counter()
        reachability_creator.create_reachability_matrix()
        elapsed = time.perf_counter() - start
        timings.append(elapsed)
        reachability = reachability_creator.reachability_matrix.shape
        egress = reachability_creator.egress_matrix.shape
        ingress = reachability_creator.ingress_matrix.shape
        matrix_stats = {
            "reachability": reachability,
            "egress": egress,
            "ingress": ingress,
        }
    return average_seconds(timings), matrix_stats


def benchmark_queries(reachability_creator, query_cases, query_count):
    query_timings = {case["name"]: [] for case in query_cases}
    total_start = time.perf_counter()

    for iteration in range(query_count):
        case = query_cases[iteration % len(query_cases)]
        query_args = {
            key: case[key]
            for key in (
                "source_namespace",
                "dest_namespace",
                "source_workload",
                "dest_workload",
                "port",
                "protocol",
            )
            if key in case
        }
        start = time.perf_counter()
        reachability_creator.query_reachability(**query_args)
        query_timings[case["name"]].append(time.perf_counter() - start)

    total_elapsed = time.perf_counter() - total_start
    per_query_average = total_elapsed / query_count
    per_case_average = {
        name: average_seconds(samples)
        for name, samples in query_timings.items()
    }
    return per_query_average, per_case_average, total_elapsed


def benchmark_policy_simplifier(application_path, workloads, base_port, policy_count, runs):
    """Time full simplifier workflow: two matrices plus compare()."""
    policies_a = generate_policies(policy_count, workloads, base_port, offset=0)
    policies_b = generate_policies(policy_count, workloads, base_port, offset=1)

    total_timings = []
    compare_timings = []
    comparison_stats = None

    for _ in range(runs):
        start = time.perf_counter()
        simplifier = PolicySimplifier.from_policy_lists(
            str(application_path), policies_a, policies_b,
        )
        total_timings.append(time.perf_counter() - start)

        compare_start = time.perf_counter()
        result = simplifier.compare()
        compare_timings.append(time.perf_counter() - compare_start)

        summary = result["summary"]
        all_rows = summary["common_rows"] | summary["rows_only_a"] | summary["rows_only_b"]
        all_cols = summary["common_cols"] | summary["cols_only_a"] | summary["cols_only_b"]
        comparison_stats = {
            "union_rows": len(all_rows),
            "union_cols": len(all_cols),
            "union_pairs": len(all_rows) * len(all_cols),
            "matrix_pairs": len(summary["common_rows"]) * len(summary["common_cols"]),
            "differences": len(result["differences"]),
        }

    return {
        "total_seconds": average_seconds(total_timings),
        "compare_seconds": average_seconds(compare_timings),
        "stats": comparison_stats,
    }


def print_matrix_size(matrix_stats):
    reach_rows, reach_cols = matrix_stats["reachability"]
    egress_rows, egress_cols = matrix_stats["egress"]
    ingress_rows, ingress_cols = matrix_stats["ingress"]
    print(
        f"           matrix size: reachability {reach_rows}x{reach_cols} "
        f"({reach_rows * reach_cols} cells)"
    )
    print(
        f"                        egress {egress_rows}x{egress_cols} "
        f"({egress_rows * egress_cols} cells), "
        f"ingress {ingress_rows}x{ingress_cols} ({ingress_rows * ingress_cols} cells)"
    )


def run_benchmark(testbed_name, testbed_config, policy_counts, query_count, matrix_runs):
    application_path = testbed_config["application"]
    workloads = testbed_config["workloads"]
    query_cases = testbed_config["query_cases"]
    base_port = testbed_config["base_port"]

    container_discoverer = ContainerDiscoverer(str(application_path))
    services = container_discoverer.services
    workload_map = container_discoverer.workloads
    namespaces = container_discoverer.namespaces

    print("Reachability performance evaluation")
    print("=================================")
    print(f"Testbed: {testbed_name}")
    print(f"Application: {application_path}")
    print(f"Matrix runs per load: {matrix_runs}")
    print(f"Lookup queries per load: {query_count}")
    print()
    print("Query types:")
    for case in query_cases:
        print(f"  - {case['name']}: {case['description']}")
    print()

    print("1. Processing time and matrix size")
    print("----------------------------------")
    processing_header = (
        f"{'Policies':>8} | {'Processing':>12} | {'Rows':>5} | {'Cols':>5} | {'Cells':>8}"
    )
    print(processing_header)
    print("-" * len(processing_header))

    lookup_results = []

    for policy_count in policy_counts:
        policies = generate_policies(policy_count, workloads, base_port)
        processing_seconds, matrix_stats = benchmark_matrix_creation(
            services, workload_map, namespaces, policies, matrix_runs,
        )

        reach_rows, reach_cols = matrix_stats["reachability"]
        print(
            f"{policy_count:8d} | {format_ms(processing_seconds):>12} | "
            f"{reach_rows:5d} | {reach_cols:5d} | {reach_rows * reach_cols:8d}"
        )
        print_matrix_size(matrix_stats)

        reachability_creator = ReachabilityCreator(
            services, workload_map, namespaces, policies,
        )
        reachability_creator.create_reachability_matrix()
        per_query_average, per_case_average, query_total_seconds = benchmark_queries(
            reachability_creator, query_cases, query_count,
        )
        lookup_results.append((policy_count, per_query_average, per_case_average, query_total_seconds))
        print()

    print("2. Lookup time (query_reachability)")
    print("----------------------------------")
    lookup_header = (
        f"{'Policies':>8} | {'Lookup avg':>12} | {'Lookup total':>12}"
    )
    print(lookup_header)
    print("-" * len(lookup_header))

    for policy_count, per_query_average, per_case_average, query_total_seconds in lookup_results:
        print(
            f"{policy_count:8d} | {format_ms(per_query_average):>12} | "
            f"{format_ms(query_total_seconds):>12}"
        )
        for case_name, case_seconds in per_case_average.items():
            print(f"           {case_name}: {format_ms(case_seconds)}")
        print()

    print("3. Policy simplification (PolicySimplifier.compare)")
    print("-----------------------------------------------")
    simplifier_header = (
        f"{'Policies':>8} | {'Total':>12} | {'Compare':>12} | "
        f"{'Union rows':>10} | {'Union cols':>10} | {'Pairs':>8}"
    )
    print(simplifier_header)
    print("-" * len(simplifier_header))

    for policy_count in policy_counts:
        result = benchmark_policy_simplifier(
            application_path, workloads, base_port, policy_count, matrix_runs,
        )
        stats = result["stats"]
        print(
            f"{policy_count:8d} | {format_ms(result['total_seconds']):>12} | "
            f"{format_ms(result['compare_seconds']):>12} | "
            f"{stats['union_rows']:10d} | {stats['union_cols']:10d} | "
            f"{stats['union_pairs']:8d}"
        )
        print(
            f"           matrix comparisons: {stats['matrix_pairs']}, "
            f"differences found: {stats['differences']}"
        )
        print()


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark reachability matrix creation, query_reachability, "
            "and policy simplifier performance."
        ),
    )
    parser.add_argument(
        "--testbed",
        choices=sorted(TESTBEDS),
        nargs="+",
        default=sorted(TESTBEDS),
        help="Application testbed(s) to benchmark (default: all)",
    )
    parser.add_argument(
        "--policy-counts",
        type=int,
        nargs="+",
        default=list(DEFAULT_POLICY_COUNTS),
        help="Number of synthetic policies to benchmark (default: 10 100 1000)",
    )
    parser.add_argument(
        "--query-count",
        type=int,
        default=DEFAULT_QUERY_COUNT,
        help="Number of queries to run per policy load (default: 1000)",
    )
    parser.add_argument(
        "--matrix-runs",
        type=int,
        default=DEFAULT_MATRIX_RUNS,
        help="Number of timed matrix builds per policy load (default: 3)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    for index, testbed_name in enumerate(args.testbed):
        testbed_config = TESTBEDS[testbed_name]
        if not testbed_config["application"].is_dir():
            print(
                f"Application path not found for {testbed_name}: "
                f"{testbed_config['application']}",
                file=sys.stderr,
            )
            raise SystemExit(1)

        if index > 0:
            print()
            print()
        run_benchmark(
            testbed_name=testbed_name,
            testbed_config=testbed_config,
            policy_counts=args.policy_counts,
            query_count=args.query_count,
            matrix_runs=args.matrix_runs,
        )


if __name__ == "__main__":
    main()
