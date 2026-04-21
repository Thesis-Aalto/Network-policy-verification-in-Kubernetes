from container_discoverer import ContainerDiscoverer
from policy_parser import PolicyParser
from reachability_creator import ReachabilityCreator

container_discoverer = ContainerDiscoverer("./application/app.yaml")
policy_parser = PolicyParser("./network_policies")
reachability_creator = ReachabilityCreator(container_discoverer.containers, policy_parser.network_policies)
reachability_creator.create_reachability_matrix()
