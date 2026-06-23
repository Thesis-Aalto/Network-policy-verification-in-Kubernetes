import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEST_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

from reachability_creator import ReachabilityCreator
from policy_parser import PolicyParser
from container_discoverer import ContainerDiscoverer
from policy_simplifier import PolicySimplifier

import json
import os

import pandas as pd


class ScenarioTest:
    def __init__(
        self,
        policy_folder_path,
        application_folder_path,
        result_folder_path,
        comparison_cases_path=None,
        query_cases_path=None,
    ):
        self.policy_folder_path = Path(policy_folder_path)
        self.application_folder_path = Path(application_folder_path)
        self.result_folder_path = Path(result_folder_path)
        self.comparison_cases_path = Path(comparison_cases_path or TEST_DIR / "comparison-cases")
        self.query_cases_path = Path(query_cases_path or TEST_DIR / "query-cases")

    def _matrix_diff_summary(self, expected_matrix, actual_matrix):
        expected_rows = set(expected_matrix.index)
        actual_rows = set(actual_matrix.index)
        expected_cols = set(expected_matrix.columns)
        actual_cols = set(actual_matrix.columns)

        missing_rows = sorted(expected_rows - actual_rows)
        extra_rows = sorted(actual_rows - expected_rows)
        missing_cols = sorted(expected_cols - actual_cols)
        extra_cols = sorted(actual_cols - expected_cols)

        if missing_rows:
            print(f"Missing rows: {missing_rows}")
        if extra_rows:
            print(f"Extra rows: {extra_rows}")
        if missing_cols:
            print(f"Missing columns: {missing_cols}")
        if extra_cols:
            print(f"Extra columns: {extra_cols}")

        common_rows = expected_matrix.index.intersection(actual_matrix.index)
        common_cols = expected_matrix.columns.intersection(actual_matrix.columns)
        if len(common_rows) > 0 and len(common_cols) > 0:
            value_diff = expected_matrix.loc[common_rows, common_cols].compare(
                actual_matrix.loc[common_rows, common_cols]
            )
            if not value_diff.empty:
                print("Value differences (expected vs actual):")
                print(value_diff)

    def matrices_equal(self, expected_matrix, actual_matrix):
        same_index = list(expected_matrix.index) == list(actual_matrix.index)
        same_columns = list(expected_matrix.columns) == list(actual_matrix.columns)
        same_values = expected_matrix.equals(actual_matrix)
        return same_index and same_columns and same_values

    def _resolve_policy_path(self, case_path, side):
        case_path = Path(case_path)
        yaml_path = case_path / f"policies-{side}.yaml"
        directory_path = case_path / f"policies-{side}"
        if yaml_path.is_file():
            return str(yaml_path)
        if directory_path.is_dir():
            return str(directory_path)
        raise FileNotFoundError(f"Missing policies-{side}.yaml or policies-{side}/ in {case_path}")

    def _load_json(self, path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def _load_comparison_expected(self, case_path):
        return self._load_json(Path(case_path) / "expected.json")

    def start_reachability_tests(self):
        total_counter = 0
        correct_counter = 0

        testbeds = [f.name for f in os.scandir(self.application_folder_path) if f.is_dir()]
        for testbed in testbeds:
            print(f"Reachability tests for {testbed} started")
            print("---------------------------------")
            print("---------------------------------")

            container_discoverer = ContainerDiscoverer(str(self.application_folder_path / testbed))
            workloads = container_discoverer.workloads
            services = container_discoverer.services
            namespaces = container_discoverer.namespaces
            policy_files = sorted(
                f.name for f in os.scandir(self.policy_folder_path / testbed)
                if f.is_file() and f.name.endswith(".yaml")
            )
            for policy_file in policy_files:
                total_counter += 1
                print("---------------------------------")
                print(f"Test case {total_counter}: {policy_file}")
                policy_parser = PolicyParser(str(self.policy_folder_path / testbed / policy_file))
                network_policies = policy_parser.network_policies

                reachability_creator = ReachabilityCreator(services, workloads, namespaces, network_policies)
                reachability_matrix = reachability_creator.create_reachability_matrix().astype(int)

                test_file = policy_file.removesuffix(".yaml") + ".csv"
                expected_matrix = pd.read_csv(
                    self.result_folder_path / testbed / test_file, index_col=0
                ).astype(int)
                result = self.matrices_equal(expected_matrix, reachability_matrix)
                if result:
                    print("Test result: CORRECT")
                    correct_counter += 1
                else:
                    print("Test Result: WRONG")
                    self._matrix_diff_summary(expected_matrix, reachability_matrix)
                    print("Expected Result:")
                    print(expected_matrix)
                    print("Application Result:")
                    print(reachability_matrix)
                print("---------------------------------")

            print("Total Results")
            print("---------------------------------")
            print(
                f"Number of Tests: {total_counter}\n"
                f"Number of Correct: {correct_counter}\n"
                f"Success Percentage: {100 * correct_counter / total_counter}"
            )
            print("---------------------------------")
            print("---------------------------------")

        return correct_counter, total_counter

    def start_policy_simplifier_tests(self):
        total_counter = 0
        correct_counter = 0

        if not self.comparison_cases_path.is_dir():
            return correct_counter, total_counter

        for testbed in sorted(os.listdir(self.comparison_cases_path)):
            testbed_path = self.comparison_cases_path / testbed
            if not testbed_path.is_dir():
                continue

            application = self.application_folder_path / testbed
            if not application.is_dir():
                continue

            print(f"PolicySimplifier tests for {testbed}")
            print("---------------------------------")

            for case_name in sorted(os.listdir(testbed_path)):
                case_path = testbed_path / case_name
                if not case_path.is_dir():
                    continue
                if not (case_path / "expected.json").is_file():
                    continue

                total_counter += 1
                expected = self._load_comparison_expected(case_path)
                policies_a = self._resolve_policy_path(case_path, "a")
                policies_b = self._resolve_policy_path(case_path, "b")

                simplifier = PolicySimplifier(str(application), policies_a, policies_b)
                result = simplifier.compare()

                print("---------------------------------")
                print(f"Test case {total_counter}: {case_name}")
                if expected.get("description"):
                    print(expected["description"])

                if result["equal"] == expected["equal"]:
                    correct_counter += 1
                    print("Test result: CORRECT")
                else:
                    print("Test Result: WRONG")
                    print(f"Expected equal={expected['equal']}, got equal={result['equal']}")
                    if result["differences"]:
                        print(f"Differences ({len(result['differences'])}):")
                        for diff in result["differences"][:5]:
                            print(diff)
                print("---------------------------------")

            print("Total Results")
            print("---------------------------------")
            print(
                f"Number of Tests: {total_counter}\n"
                f"Number of Correct: {correct_counter}\n"
                f"Success Percentage: {100 * correct_counter / total_counter if total_counter else 0}"
            )
            print("---------------------------------")
            print("---------------------------------")

        return correct_counter, total_counter

    def start_query_reachability_tests(self):
        total_counter = 0
        correct_counter = 0

        if not self.query_cases_path.is_dir():
            return correct_counter, total_counter

        for testbed in sorted(os.listdir(self.query_cases_path)):
            testbed_path = self.query_cases_path / testbed
            if not testbed_path.is_dir():
                continue

            application = self.application_folder_path / testbed
            policy_folder = self.policy_folder_path / testbed
            if not application.is_dir() or not policy_folder.is_dir():
                continue

            print(f"query_reachability tests for {testbed}")
            print("---------------------------------")

            container_discoverer = ContainerDiscoverer(str(application))
            workloads = container_discoverer.workloads
            services = container_discoverer.services
            namespaces = container_discoverer.namespaces

            for case_name in sorted(os.listdir(testbed_path)):
                case_path = testbed_path / case_name
                expected_path = case_path / "expected.json"
                if not case_path.is_dir() or not expected_path.is_file():
                    continue

                case_data = self._load_json(expected_path)
                policy_file = case_data["policy_file"]
                policy_parser = PolicyParser(str(policy_folder / policy_file))
                reachability_creator = ReachabilityCreator(
                    services, workloads, namespaces, policy_parser.network_policies,
                )
                reachability_creator.create_reachability_matrix()

                for query_case in case_data["queries"]:
                    total_counter += 1
                    query = query_case["query"]
                    expected = query_case["expected"]
                    result = reachability_creator.query_reachability(**query)

                    print("---------------------------------")
                    print(f"Test case {total_counter}: {case_name}/{query_case['name']}")
                    if query_case.get("description"):
                        print(query_case["description"])

                    passed = False
                    if expected.get("invalid"):
                        passed = result == "invalid query"
                        if not passed:
                            print("Test Result: WRONG")
                            print("Expected invalid query")
                            print(f"Got: {result}")
                    else:
                        if result == "invalid query":
                            print("Test Result: WRONG")
                            print("Expected a valid query result")
                        elif (
                            result["reachable"] == expected["reachable"]
                            and result["tier"] == expected["tier"]
                        ):
                            passed = True
                        else:
                            print("Test Result: WRONG")
                            print(
                                f"Expected reachable={expected['reachable']}, tier={expected['tier']}"
                            )
                            print(f"Got reachable={result['reachable']}, tier={result['tier']}")
                            if result.get("deciding_match"):
                                print(f"Deciding match: {result['deciding_match']}")

                    if passed:
                        correct_counter += 1
                        print("Test result: CORRECT")
                    print("---------------------------------")

            print("Total Results")
            print("---------------------------------")
            print(
                f"Number of Tests: {total_counter}\n"
                f"Number of Correct: {correct_counter}\n"
                f"Success Percentage: {100 * correct_counter / total_counter if total_counter else 0}"
            )
            print("---------------------------------")
            print("---------------------------------")

        return correct_counter, total_counter

    def start_test(self):
        reachability_correct, reachability_total = self.start_reachability_tests()
        simplifier_correct, simplifier_total = self.start_policy_simplifier_tests()
        query_correct, query_total = self.start_query_reachability_tests()
        return (
            reachability_correct + simplifier_correct + query_correct,
            reachability_total + simplifier_total + query_total,
        )


if __name__ == "__main__":
    scenario_test = ScenarioTest(
        policy_folder_path=TEST_DIR / "network_policies",
        application_folder_path=TEST_DIR / "application",
        result_folder_path=TEST_DIR / "expected_result",
        comparison_cases_path=TEST_DIR / "comparison-cases",
        query_cases_path=TEST_DIR / "query-cases",
    )
    correct, total = scenario_test.start_test()
    if correct != total:
        raise SystemExit(1)
