from policy_parser import Policy, PolicyRule

class ReachabilityCreator():
    def __init__(self, containers, network_policies):
        self.reachability_matrix = {}
        self.containers = containers
        self.network_policies = network_policies
    
    def create_reachability_matrix(self):
        egress_matrix = self.initialize_matrix()
        ingress_matrix = self.initialize_matrix()

        for policy in self.network_policies:
            source_containers = self.find_selected_containers(policy)
            for rule in policy.rules:
                target_containers = self.find_selected_containers(rule)
                if rule.policy_type == "Ingress":
                    self.fill_matrix(source_containers, target_containers, ingress_matrix)
                else:
                    self.fill_matrix(source_containers, target_containers, egress_matrix)
        self.intersect_egress_and_igress(egress_matrix, ingress_matrix)
        print(self.reachability_matrix)
                    
    def find_selected_containers(self, policy_component):
        selected_containers = []
        labels_dict = {}
        namespace = ""
        if type(policy_component) == Policy:
            labels_dict = policy_component.source_labels
        else:
            labels_dict = policy_component.target_labels
            namespace = policy_component.namespace_label
        for container in self.containers:
            if type(policy_component) == Policy and policy_component.namespace != container.namespace:
                continue
            is_added = True
            for key, value in labels_dict.items():
                if key not in container.labels or container.labels[key] != value:
                    is_added = False
            if type(policy_component) == PolicyRule and namespace != container.namespace:
                is_added = False
            if is_added:
                selected_containers.append(container)
        return selected_containers
    
    def is_match_container_policy(self, container, policy_rule):
        for port in policy_rule.ports:
            if port.portNumber == container.port:
                return True
        return False
    
    def initialize_matrix(self):
        matrix = {}
        for s_container in self.containers:
            matrix[s_container.identity] = {}
            for t_container in self.containers:
                if s_container.identity == t_container.identity:
                    matrix[s_container.identity][s_container.identity] = 0
                else:
                    matrix[s_container.identity][t_container.identity] = 1
        return matrix
    
    def fill_matrix(self, source_containers, target_containers, matrix):  
        for s_container in source_containers:
            for t_container in target_containers:
                if matrix[s_container.identity][s_container.identity] == 1:
                    matrix[s_container.identity][t_container.identity] = 1
                else:
                    self.zero_all_row(s_container, matrix)
                    matrix[s_container.identity][t_container.identity] = 1
                    matrix[s_container.identity][s_container.identity] = 1
            if len(target_containers) == 0 and matrix[s_container.identity][s_container.identity] == 0:
                self.zero_all_row(s_container, matrix)
                matrix[s_container.identity][s_container.identity] = 1
    
    def zero_all_row(self, source_container, matrix):
        for container in self.containers:
            if container.identity != source_container.identity:
                matrix[source_container.identity][container.identity] = 0

    def intersect_egress_and_igress(self, egress_matrix, ingress_matrix):
        for s_container in self.containers:
            self.reachability_matrix[s_container.identity] = {}
            for t_container in self.containers:
                if s_container.identity == t_container.identity:
                    self.reachability_matrix[s_container.identity][t_container.identity] = 1
                else:
                    self.reachability_matrix[s_container.identity][t_container.identity] = egress_matrix[s_container.identity][t_container.identity] and ingress_matrix[t_container.identity][s_container.identity] 

        



    




    
    