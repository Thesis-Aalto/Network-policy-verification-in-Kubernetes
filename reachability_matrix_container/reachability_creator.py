from policy_parser import Policy, PolicyRule, PolicyParser
from container_discoverer import ContainerDiscoverer


class ReachabilityCreator():
    def __init__(self, containers, network_policies):
        self.reachability_matrix = {}
        self.containers = containers
        self.network_policies = network_policies
    
    def create_reachability_matrix(self):
        egress_matrix = self.initialize_matrix()
        ingress_matrix = self.initialize_matrix()
        is_policy_applied={}
        self.fill_is_policy_applied(is_policy_applied)

        for policy in self.network_policies:
            source_containers = self.find_selected_containers(policy)
            if len(policy.rules) == 0:
                target_containers = []
                for policy_type in policy.policy_types:
                    if policy_type == "Ingress":
                        self.fill_matrix(source_containers, target_containers, ingress_matrix, "Ingress", is_policy_applied)
                    else:
                        self.fill_matrix(source_containers, target_containers, egress_matrix, "Egress", is_policy_applied)
            for rule in policy.rules:
                target_containers = self.find_selected_containers(rule)
                if rule.policy_type == "Ingress":
                    self.fill_matrix(source_containers, target_containers, ingress_matrix, "Ingress", is_policy_applied)
                else:
                    self.fill_matrix(source_containers, target_containers, egress_matrix, "Egress", is_policy_applied)
        self.intersect_egress_and_igress(egress_matrix, ingress_matrix)
        return self.reachability_matrix
                    
    def find_selected_containers(self, policy_component):
        selected_containers = []
        labels_dict = {}
        namespace = ""
        if type(policy_component) == Policy:
            labels_dict = policy_component.source_labels
        else:
            labels_dict = policy_component.target_labels
            namespace = policy_component.namespace_label
        if labels_dict == {}:
            if type(policy_component) == PolicyRule and len(policy_component.ports) != 0:
                selected_containers = []
                for container in self.containers:
                    if self.is_match_container_policy(container, policy_component):
                        selected_containers.append(container) 

                return selected_containers
            else:
                return self.containers
        for container in self.containers:
            if type(policy_component) == Policy and policy_component.namespace != container.namespace:
                continue
            is_added = True
            for key, value in labels_dict.items():
                if key not in container.labels or container.labels[key] != value:
                    is_added = False
            if type(policy_component) == PolicyRule and (namespace != container.namespace or not self.is_match_container_policy(container, policy_component)):
                is_added = False
            if is_added:
                selected_containers.append(container)
        return selected_containers
    
    def is_match_container_policy(self, container, policy_rule):
        if len(policy_rule.ports) == 0:
            return True
        for port in policy_rule.ports:
            if port.portNumber == container.port:
                return True
            for service in container.services:
                for servicePort in service.ports:
                    if port.portNumber == servicePort.target_port:
                        container.is_maybe = True
                        return True
        return False
    
    def initialize_matrix(self):
        matrix = {}
        for s_container in self.containers:
            matrix[s_container.identity] = {}
            for t_container in self.containers:
                matrix[s_container.identity][t_container.identity] = 1
        return matrix
    
    def fill_matrix(self, source_containers, target_containers, matrix, policy_type, is_policy_applied):  
        for s_container in source_containers:
            for t_container in target_containers:
                if is_policy_applied[s_container.identity][policy_type] == 1:
                    matrix[s_container.identity][t_container.identity] = 2 if t_container.is_maybe else 1
                else:
                    self.zero_all_row(s_container, matrix)
                    matrix[s_container.identity][t_container.identity] = 2 if t_container.is_maybe else 1
                    is_policy_applied[s_container.identity][policy_type] = 1
                t_container.is_maybe = False
            if len(target_containers) == 0 and is_policy_applied[s_container.identity][policy_type] == 0:
                self.zero_all_row(s_container, matrix)
                is_policy_applied[s_container.identity][policy_type] = 1


    def fill_is_policy_applied(self, policy_matrix):
        for container in self.containers:
            policy_matrix[container.identity] = {}
            for policy_type in ["Ingress", "Egress"]:
                policy_matrix[container.identity][policy_type] = 0
        
    
    def zero_all_row(self, source_container, matrix):
        for container in self.containers:
            matrix[source_container.identity][container.identity] = 0

    def intersect_egress_and_igress(self, egress_matrix, ingress_matrix):
        for s_container in self.containers:
            self.reachability_matrix[s_container.identity] = {}
            for t_container in self.containers:
                self.reachability_matrix[s_container.identity][t_container.identity] = egress_matrix[s_container.identity][t_container.identity] and ingress_matrix[t_container.identity][s_container.identity] 


if __name__ == "__main__":
    container_discoverer = ContainerDiscoverer("./application/app.yaml")
    policy_parser = PolicyParser("./network_policies")

    containers = container_discoverer.containers
    reachability_creator = ReachabilityCreator(containers, policy_parser.network_policies)

    reachability_matrix = reachability_creator.create_reachability_matrix()
    print(reachability_matrix)