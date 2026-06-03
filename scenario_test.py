from reachability_creator import ReachabilityCreator
from policy_parser import PolicyParser
from container_discoverer import ContainerDiscoverer

import pandas as pd
import sys


symbol_mapping = {'✗': 0, '✓': 1, '?': 2}

class ScenarioTest:
    def __init__(self, policy_path, application_path, result_path):
        self.policy_path = policy_path
        self.application_path = application_path
        self.result_path = result_path

        self.expected_result = self.get_expected_result()
        self.reachability_creator_result = self.get_reachability_creator_result()
    
    def get_expected_result(self):
        df = pd.read_csv(self.result_path, index_col=0)
        df_mapped = df.replace(symbol_mapping)
        csv_dict = df_mapped.to_dict(orient='index')
        return csv_dict
    
        
    def get_reachability_creator_result(self):
       policy_parser = PolicyParser(self.policy_path)
       container_discoverer = ContainerDiscoverer(self.application_path)
       reachability_creator =  ReachabilityCreator(container_discoverer.workloads, policy_parser.network_policies)
       return reachability_creator.create_reachability_matrix()

    def compare_results(self):
        print("--- Starting Scenario Test Comparison ---")
        mismatches = []
        matches_count = 0
        
        for src_workload, destinations in self.expected_result.items():
            if src_workload not in self.reachability_creator_result:
                print(f"[WARNING] Source workload '{src_workload}' missing from generated results.")
                continue
                
            for dest_workload, expected_val in destinations.items():
                if dest_workload not in self.reachability_creator_result[src_workload]:
                    print(f"[WARNING] Destination '{dest_workload}' missing for source '{src_workload}' in generated results.")
                    continue
                
                generated_val = self.reachability_creator_result[src_workload][dest_workload]
                
                
                if generated_val == expected_val:
                    matches_count += 1
                else:
                    mismatches.append({
                        'source': src_workload,
                        'destination': dest_workload,
                        'expected': expected_val,
                        'generated': generated_val
                    })
        
        # --- Print Results Summary ---
        print(f"\nComparison Complete:")
        print(f"  Total Matches: {matches_count}")
        print(f"  Total Mismatches: {len(mismatches)}")
        
        if mismatches:
            print("\nDetailed Mismatches:")
            # Inverse mapping to print human-readable symbols in the console
            inv_symbol_mapping = {v: k for k, v in symbol_mapping.items()}
            
            for m in mismatches:
                exp_sym = inv_symbol_mapping.get(m['expected'], m['expected'])
                gen_sym = inv_symbol_mapping.get(m['generated'], m['generated'])
                print(f"  ✗ {m['source']} -> {m['destination']} | Expected: {exp_sym} ({m['expected']}), Got: {gen_sym} ({m['generated']})")
            return False
            
        print("\n✓ Success! Generated matrix matches the expected matrix perfectly.")
        return True
if __name__ == "__main__":
    application_folder_path = "./application/aks-store-demo"
    policy_folder_path = "./network_policies/example"
    result_path = "./expected_result/deny-all.csv"

    if len(sys.argv) > 4:
        application_folder_path = sys.argv[1]
        policy_folder_path = sys.argv[2] 
        result_path = sys.argv[3]
    elif len(sys.argv) > 3:
        application_folder_path = sys.argv[1]
        policy_folder_path = sys.argv[2] 
    elif len(sys.argv) > 2:
        application_folder_path = sys.argv[1]

    scenario_test = ScenarioTest(policy_folder_path, application_folder_path, result_path)
    scenario_test.compare_results()