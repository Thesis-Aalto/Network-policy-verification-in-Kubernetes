from reachability_creator import ReachabilityCreator
from policy_parser import PolicyParser
from container_discoverer import ContainerDiscoverer

import pandas as pd
import os


class ScenarioTest:
    def __init__(self, policy_folder_path, application_folder_path, result_folder_path):
        self.policy_folder_path = policy_folder_path
        self.application_folder_path = application_folder_path
        self.result_folder_path = result_folder_path

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

    def start_test(self):
        testbeds = [f.name for f in os.scandir(self.application_folder_path) if f.is_dir()]
        for testbed in testbeds:
           print(f"Tests for {testbed} started")
           print("---------------------------------")
           print("---------------------------------")
           total_counter = 0
           correct_counter = 0
           
           container_discoverer = ContainerDiscoverer(self.application_folder_path+"/"+testbed)
           workloads = container_discoverer.workloads
           services = container_discoverer.services
           namespaces = container_discoverer.namespaces
           policy_files = sorted(
               f.name for f in os.scandir(self.policy_folder_path+"/"+testbed)
               if f.is_file() and f.name.endswith(".yaml")
           )
           for policy_file in policy_files:
               total_counter +=1
               print("---------------------------------")
               print(f"Test case {total_counter}: {policy_file}")
               policy_parser = PolicyParser(self.policy_folder_path+"/"+testbed+"/"+policy_file)
               network_policies = policy_parser.network_policies

               reachability_creator = ReachabilityCreator(services, workloads, namespaces, network_policies)
               reachability_matrix = reachability_creator.create_reachability_matrix().astype(int)

               test_file = policy_file.removesuffix(".yaml") + ".csv"
               expected_matrix = pd.read_csv(
                   self.result_folder_path+"/"+testbed+"/"+test_file, index_col=0
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
           print(f"Number of Tests: {total_counter}\nNumber of Correct: {correct_counter}\nSuccess Percentage: {100*correct_counter/total_counter}")
           print("---------------------------------")
           print("---------------------------------")
                
    
if __name__ == "__main__":
    application_folder_path = "./application"
    policy_folder_path = "./network_policies"
    result_folder_path = "./expected_result"


    scenario_test = ScenarioTest(policy_folder_path, application_folder_path, result_folder_path)
    scenario_test.start_test()