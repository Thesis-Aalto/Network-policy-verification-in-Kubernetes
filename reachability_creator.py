from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer

import sys
import pandas as pd

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 2000)

###TODO: Add internet as both row and column
###TODO: Create NetworkPolicyRecommender to recommend network policies
class ReachabilityCreator():
    def __init__(self, services, workloads, namespaces, network_policies):
        self.services = services
        self.workloads = workloads
        self.namespaces = namespaces
        self.network_policies = network_policies


        self.ingress_matrix = self.initialize_matrix()
        self.egress_matrix = self.initialize_matrix()
        # 1 Ingress, 2 Egress, 3 Both
        self.is_policy_applied = {}
        self.reachability_matrix = {}
    
    def create_reachability_matrix(self):
        for policy in self.network_policies:
            self.apply_network_policy(policy)
        self.intersect_egress_and_igress()
        return self.reachability_matrix
    
    def initialize_matrix(self):
        new_matrix = pd.DataFrame()
        for source_namespace in self.namespaces:
            for target_namespace in self.namespaces:
                new_matrix.at[source_namespace.name, target_namespace.name] = 1
        return new_matrix


    def apply_network_policy(self, policy):
        if len(policy.rules) == 0:
            sources = {}
            targets = {}
            if policy.source_labels == {}:
                sources[policy.namespace] = 1
            else:
                for workload in self.workloads.get(policy.namespace, []):
                    for key, value in policy.source_labels.items():
                        if key in workload.labels and workload.labels[key] == value:
                            sources[workload.namespace+"_"+workload.name] = 1
            for policy_type in policy.policy_types:
                self.fill_matrix(sources, targets, policy_type, policy.namespace)


        for rule in policy.rules:
            sources= {}
            targets = {}

            targeted_namespaces = []
            for namespace in self.namespaces:
                for key, value in rule.namespace_label.items():
                    if key in namespace.labels and namespace.labels[key] == value:
                        targeted_namespaces.append(namespace.name)

            if len(targeted_namespaces) == 0:
                targeted_namespaces.append(policy.namespace)
            if rule.policy_type == "Egress":
                # Finding Sources
                if policy.source_labels == {}:
                    sources[policy.namespace] = 1
                else:
                    for workload in self.workloads.get(policy.namespace, []):
                        for key, value in policy.source_labels.items():
                            if key in workload.labels and workload.labels[key] == value:
                                sources[workload.namespace+"_"+workload.name] = 1
                ### Finding targets
                if rule.target_labels == {}:
                    if len(rule.ports) == 0:
                        for namespace in targeted_namespaces:
                            if namespace in self.workloads:
                                targets[namespace]=1
                    else:
                        for namespace in targeted_namespaces:
                            if namespace in self.workloads:
                                for port in rule.ports:
                                    target = namespace+"_"+str(port.portNumber)+"_"+port.protocol
                                    targets[target]=1
                else:
                    if len(rule.ports) == 0:
                        for namespace in targeted_namespaces:
                            for workload in self.workloads.get(namespace, []):
                                for key, value in rule.target_labels.items():
                                    if key in workload.labels and workload.labels[key] == value:
                                        target = namespace+"_"+workload.name
                                        targets[target]=1

                            for service in self.services.get(namespace, []):
                                for key, value in rule.target_labels.items():
                                    if key in service.selector and service.selector[key] == value:
                                        target = namespace+"_"+service.identity
                                        targets[target]=1
                        
                    else:
                        for namespace in targeted_namespaces:
                            for workload in self.workloads.get(namespace, []):
                                for key, value in rule.target_labels.items():
                                    if key in workload.labels and workload.labels[key] == value:
                                        for container in workload.containers:
                                            for port in rule.ports:
                                                #Not included in policy mismatch, might be a problem. All traffic to the target must be denied in this case.
                                                if port.portNumber == container.port:
                                                    target = namespace+"_"+workload.name+"_"+str(container.port)+"_"+port.protocol
                                                    targets[target]=1

                            for service in self.services.get(namespace, []):
                                for key, value in rule.target_labels.items():
                                    if key in service.selector and service.selector[key] == value:
                                        for port in service.ports:
                                            for rule_port in rule.ports:
                                                if port.port == rule_port.portNumber:
                                                    target = namespace+"_"+service.identity+"_"+str(rule_port.portNumber)+"_"+rule_port.protocol
                                                    targets[target] = 1
            else:
                ### Finding sources
                for namespace in targeted_namespaces:
                    if rule.target_labels == {}:
                        sources[namespace]=1
                    else:
                        for workload in self.workloads.get(namespace, []):
                            for key, value in rule.target_labels.items():
                                if key in workload.labels and workload.labels[key] == value:
                                    sources[workload.namespace+"_"+workload.name]=1
                    
                if policy.source_labels == {}:
                    if len(rule.ports) == 0:
                        targets[policy.namespace]=1
                    else:
                        for port in rule.ports:
                            targets[policy.namespace+"_"+str(port.portNumber)+"_"+port.protocol]=1
                else:
                    if len(rule.ports) == 0:
                        for workload in self.workloads.get(policy.namespace, []):
                            for key, value in policy.source_labels.items():
                                if key in workload.labels and workload.labels[key] == value:
                                    target = workload.namespace+"_"+workload.name
                                    targets[target] = 1
                        for service in self.services.get(policy.namespace, []):
                            for key, value in policy.source_labels.items():
                                if key in service.selector and service.selector[key] == value and service.namespace == policy.namespace:
                                    target = policy.namespace+"_"+service.identity
                                    targets[target] = 1
                                    
                    else:
                        for workload in self.workloads.get(policy.namespace, []):
                            for key, value in policy.source_labels.items():
                                if key in workload.labels and workload.labels[key] == value:
                                    for container in workload.containers:
                                        for port in rule.ports:
                                            if port.portNumber == container.port:
                                                target = policy.namespace+"_"+workload.name+"_"+str(container.port)+"_"+port.protocol
                                                targets[target]=1
                        for service in self.services.get(policy.namespace, []):
                            for key, value in policy.source_labels.items():
                                if key in service.selector and service.selector[key] == value:
                                    for port in service.ports:
                                        for rule_port in rule.ports:
                                            if port.port == rule_port.portNumber:
                                                target = policy.namespace+"_"+service.identity+"_"+str(rule_port.portNumber)+"_"+rule_port.protocol
                                                targets[target] = 1
            self.fill_matrix(sources, targets, rule.policy_type, policy.namespace)

    ###TODO: Fix port mismatch situation
    def fill_matrix(self, source_workloads, target_endpoints, policy_type, policy_namespace):
        if policy_type == "Ingress":
            #Deny all case
            if len(target_endpoints) == 0:
                for source in source_workloads:
                    self.ingress_matrix.at[source, policy_namespace] = 0
                    if policy_namespace not in self.is_policy_applied:
                        self.is_policy_applied[policy_namespace] = 1
                    elif self.is_policy_applied[policy_namespace] == 2:
                        self.is_policy_applied[policy_namespace] = 3

            for target in target_endpoints:
                for source in source_workloads: 
                    if source not in self.ingress_matrix.index:
                        for col in self.ingress_matrix.columns:
                            if col in self.is_policy_applied and (self.is_policy_applied[col] == 1 or self.is_policy_applied[col] == 3):
                                self.ingress_matrix.at[source, col] = 0
                    self.ingress_matrix.at[source, target] = 1
                    self.ingress_matrix.loc[source] = self.ingress_matrix.loc[source].fillna(1)
                    self.ingress_matrix[target] = self.ingress_matrix[target].fillna(0)

                    #Update Egress
                    if source not in self.egress_matrix.index:
                        self.egress_matrix.loc[source] = 1
                    if target not in self.egress_matrix.columns:
                        self.egress_matrix[target] = 1
                        for row in self.egress_matrix.index:
                            if row in self.is_policy_applied and (self.is_policy_applied[row] == 2 or self.is_policy_applied[row]==3):
                                self.egress_matrix.at[row, target] = 0
                        
                target_components = target.split("_")
                while len(target_components) > 2:
                    #Update Ingress
                    target_components.pop()
                    new_endpoint = "_".join(target_components)
                    self.update_is_policy_applied(policy_type, new_endpoint)
                    if new_endpoint not in self.is_policy_applied or self.is_policy_applied[new_endpoint] == 1 or self.is_policy_applied[new_endpoint] == 3:
                        self.ingress_matrix[new_endpoint] = 0
                    

                    #Update Egress
                    if new_endpoint not in self.egress_matrix.columns:
                        self.egress_matrix[new_endpoint] = 1
                        for row in self.egress_matrix.index:
                            if row in self.is_policy_applied and (self.is_policy_applied[row] == 2 or self.is_policy_applied[row]==3):
                                self.egress_matrix.at[row, new_endpoint] = 0
                    
                    if new_endpoint not in self.is_policy_applied:
                        self.is_policy_applied[new_endpoint] = 1
                    elif self.is_policy_applied[new_endpoint] == 2:
                        self.is_policy_applied[new_endpoint] = 3


                self.update_is_policy_applied(policy_type, target)
                
        else:
            for source in source_workloads:
                #Deny all case
                if len(target_endpoints) == 0:
                    self.egress_matrix.at[source, policy_namespace] = 0
                for target in target_endpoints:
                    target_components = target.split("_")
                    while len(target_components) > 2:
                        target_components.pop()
                        new_endpoint = "_".join(target_components)
                        self.update_is_policy_applied(policy_type, new_endpoint)
                        if new_endpoint not in self.egress_matrix.columns:
                            self.egress_matrix[new_endpoint] = 0
                            for row in self.egress_matrix.index:
                                if row not in self.is_policy_applied or self.is_policy_applied[row] == 1:
                                    self.egress_matrix.at[row, new_endpoint] = 1
                        #Update Ingress
                        if new_endpoint not in self.ingress_matrix.columns:
                            self.ingress_matrix[new_endpoint] = 1

                    if source not in self.is_policy_applied or self.is_policy_applied[source] == 1:
                        self.egress_matrix.loc[source] = 0
                    for row in self.egress_matrix.index:
                        if row in self.is_policy_applied and (self.is_policy_applied[row] == 2 or self.is_policy_applied[row]==3):
                            self.egress_matrix.at[row, target] = 0
                    self.egress_matrix.at[source, target] = 1
                    self.egress_matrix[target] = self.egress_matrix[target].fillna(1)
                    self.egress_matrix.loc[source] = self.egress_matrix.loc[source].fillna(0)

                    #Update Ingress
                    if target not in self.ingress_matrix.columns:
                        self.ingress_matrix[target] = 1
                    if source not in self.ingress_matrix.index:
                        self.ingress_matrix.loc[source] = 1
                        for col in self.ingress_matrix.columns:
                            if col in self.is_policy_applied and (self.is_policy_applied[col] == 1 or self.is_policy_applied[col] == 3):
                                self.ingress_matrix.at[source, col] = 0
                    else:
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
        df_reachability = self.egress_matrix * self.ingress_matrix
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