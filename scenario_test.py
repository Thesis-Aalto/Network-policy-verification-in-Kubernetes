from reachability_creator import ReachabilityCreator
from policy_parser import PolicyParser
from container_discoverer import ContainerDiscoverer

import pandas as pd
import os


symbol_mapping = {'✗': 0, '✓': 1, '?': 2}

class ScenarioTest:
    def __init__(self, policy_folder_path, application_folder_path, result_folder_path):
        self.policy_folder_path = policy_folder_path
        self.application_folder_path = application_folder_path
        self.result_folder_path = result_folder_path

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
           policy_files = [f.name for f in os.scandir(self.policy_folder_path+"/"+testbed) if f.is_file()]
           for policy_file in policy_files:
               total_counter +=1
               print("---------------------------------")
               print(f"Test case {total_counter}: {policy_file}")
               policy_parser = PolicyParser(self.policy_folder_path+"/"+testbed+"/"+policy_file)
               network_policies = policy_parser.network_policies

               reachability_creator = ReachabilityCreator(services, workloads, namespaces, network_policies)
               reachability_matrix = reachability_creator.create_reachability_matrix().astype(float)

               test_file = policy_file.split(".")[0]+".csv"
               expected_matrix = pd.read_csv(self.result_folder_path+"/"+testbed+"/"+test_file, index_col=0).astype(float)
               result=expected_matrix.equals(reachability_matrix)
               if result==True:
                   print("Test result: CORRECT")
                   correct_counter += 1
               else:
                   print("Test Result: WRONG")
                   print("Expected Result:")
                   print(expected_matrix)
                   print("Application Result")
                   print(reachability_matrix)
               print("---------------------------------")
           print("Total Results")
           print("---------------------------------")
           print(f"Number of Tests: {total_counter}\nNumber of Correct: {correct_counter}\nSuccess Percentage: {correct_counter/total_counter}")
           print("---------------------------------")
           print("---------------------------------")
                
    
if __name__ == "__main__":
    application_folder_path = "./application"
    policy_folder_path = "./network_policies"
    result_folder_path = "./expected_result"


    scenario_test = ScenarioTest(policy_folder_path, application_folder_path, result_folder_path)
    scenario_test.start_test()