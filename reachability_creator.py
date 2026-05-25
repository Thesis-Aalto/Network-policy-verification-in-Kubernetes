from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer

import sys
import pandas as pd

###TODO: Add services as endpoints to the matrix
###TODO: Add internet as both row and column
###TODO: Create a scenario tester X
###TODO: Create NetworkPolicyRecommender to recommend network policies
class ReachabilityCreator():
    def __init__(self, workloads, network_policies):
        self.workloads = workloads
        self.network_policies = network_policies

        self.ingress_matrix = self.initialize_matrix()
        self.egress_matrix = self.initialize_matrix()
        self.reachability_matrix = {}
        self.is_policy_applied = {}
        self.fill_is_policy_applied()
    
    def create_reachability_matrix(self):
        for policy in self.network_policies:
            self.apply_network_policy(policy)
        self.intersect_egress_and_igress()
        return self.reachability_matrix
                    
    def apply_network_policy(self, policy):
        source_workloads = []
        target_containers = []
        for rule in policy.rules:
            if rule.policy_type == "Ingress":
                for workload in self.workloads:
                    if workload.namespace == rule.namespace_label:
                        for key, value in rule.target_labels.items():
                            if key in workload.labels and workload.labels[key] == value:
                                source_workloads.append(workload)

                    if workload.namespace == policy.namespace:
                        for key,value in policy.source_labels.items():
                            if key in workload.labels and workload.labels[key] == value:
                                for container in workload.containers:
                                    if self.is_match_ports(container, rule, workload.services):
                                        target_containers.append(container)
                self.fill_matrix(source_workloads, target_containers, self.ingress_matrix, rule.policy_type)
                    
            else:
                for workload in self.workloads:
                    if workload.namespace == policy.namespace:
                        for key, value in policy.source_labels.items():
                            if key in workload.labels and workload.labels[key] == value:
                                source_workloads.append(workload)
                    
                    if workload.namespace == rule.namespace_label:
                        for key,value in rule.target_labels.items():
                            if key in workload.labels and workload.labels[key] == value:
                                for container in workload.containers:
                                    if self.is_match_ports(container, rule, workload.services):
                                        target_containers.append(container)
                self.fill_matrix(source_workloads, target_containers, self.egress_matrix, rule.policy_type)
        ##Exceptional Case: Deny All
        if len(policy.rules) == 0:
            for policy_type in policy.policy_types:
                source_workloads = []
                target_containers = []
                if policy_type == "Egress":
                    for workload in self.workloads:
                        if workload.namespace == policy.namespace:
                            source_workloads.append(workload)
                    self.fill_matrix(source_workloads, target_containers, self.egress_matrix, policy_type)
                else:
                    for workload in self.workloads:
                        if workload.namespace == policy.namespace:
                            for t_container in workload.containers:
                                target_containers.append(t_container)
                    self.fill_matrix(source_workloads, target_containers, self.ingress_matrix, policy_type)

    def is_match_ports(self, container, policy_rule, services):
        if len(policy_rule.ports) == 0:
            return True
        for port in policy_rule.ports:
            if port.portNumber == container.port:
                return True
            for service in services:
                for servicePort in service.ports:
                    if port.portNumber == servicePort.target_port:
                        container.is_maybe = True
                        return True
        return False
    
    def initialize_matrix(self):
        matrix = {}
        for s_workload in self.workloads:
            matrix[s_workload.name] = {}
            for t_workload in self.workloads:
                for t_container in t_workload.containers:
                    matrix[s_workload.name][t_container.identity] = 1
        return matrix
    
    #TODO: Discuss about maybe situation
    def fill_matrix(self, source_workloads, target_containers, matrix, policy_type):
        if policy_type == "Ingress":
            for t_container in target_containers:
                if len(source_workloads) == 0:
                    self.zero_all_col(t_container, matrix)
                for s_workload in source_workloads:
                    if self.is_policy_applied[t_container.identity]:
                        matrix[s_workload.name][t_container.identity] = 1
                    else:
                        self.zero_all_col(t_container, matrix)
                        matrix[s_workload.name][t_container.identity] = 1
                        self.is_policy_applied[t_container.identity] = 1
        else:
            for s_workload in source_workloads:
                if len(target_containers)==0:
                      self.zero_all_row(s_workload, matrix)
                for t_container in target_containers:
                    if self.is_policy_applied[s_workload.name]:
                        matrix[s_workload.name][t_container.identity] = 1
                    else:
                        self.zero_all_row(s_workload, matrix)
                        matrix[s_workload.name][t_container.identity] = 1
                        self.is_policy_applied[s_workload.name]
                    

    ### is_policy_applied shows that is any policy applied to workloads or endpoints
    def fill_is_policy_applied(self):
        for workload in self.workloads:
            self.is_policy_applied[workload.name] = 0
            for container in workload.containers:
                self.is_policy_applied[container.identity] = 0
        
    
    def zero_all_row(self, source_workload, matrix):
        for workload in self.workloads:
            for container in workload.containers:
                matrix[source_workload.name][container.identity] = 0

    def zero_all_col(self, container, matrix):
        for workload in self.workloads:
            matrix[workload.name][container.identity] = 0

    def intersect_egress_and_igress(self):
        df_egress = pd.DataFrame(self.egress_matrix).T
        df_ingress = pd.DataFrame(self.ingress_matrix).T
        
        df_reachability = df_egress & df_ingress
        self.reachability_matrix = df_reachability.to_dict(orient="index")

    
    def print_reachability_table(self):
        if not self.reachability_matrix:
            print("Empty reachability matrix.")
            return

        sources = list(self.reachability_matrix.keys())
        targets = list(next(iter(self.reachability_matrix.values())).keys())

        col_w = max(max(len(s) for s in sources), max(len(t) for t in targets), 8) + 2

        SYMBOLS = {0: "✗", 1: "✓", 2: "?"}

        header = f"{'':>{col_w}} |" + "".join(f" {t:^{col_w}} |" for t in targets)
        separator = "-" * len(header)

        print(separator)
        print(header)
        print(separator)

        for source in sources:
            row = f"{source:>{col_w}} |"
            for target in targets:
                val = self.reachability_matrix[source].get(target, 0)
                symbol = SYMBOLS.get(val, str(val))
                row += f" {symbol:^{col_w}} |"
            print(row)

        print(separator)
        print(f"\nLegend:  ✓ = allowed (1)   ? = maybe (2)   ✗ = denied (0)")

if __name__ == "__main__":
    application_folder_path = "./application/aks-store-demo"
    policy_folder_path = "./network_policies/example"
    if len(sys.argv) > 2:
        application_folder_path = sys.argv[1]
        policy_folder_path = sys.argv[2] 
    elif len(sys.argv) > 1:
        application_folder_path = sys.argv[1]

    container_discoverer = ContainerDiscoverer(application_folder_path)
    policy_parser = PolicyParser(policy_folder_path)

    workloads = container_discoverer.workloads
    reachability_creator = ReachabilityCreator(workloads, policy_parser.network_policies)

    reachability_matrix = reachability_creator.create_reachability_matrix()
    reachability_creator.print_reachability_table()