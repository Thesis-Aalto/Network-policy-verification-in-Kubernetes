from container_discoverer import ContainerDiscoverer
from policy_parser import PolicyParser
from reachability_creator import ReachabilityCreator
from kubesonde_test import KubesondeTest

container_discoverer = ContainerDiscoverer("./application/app.yaml")
policy_parser = PolicyParser("./network_policies")

containers = container_discoverer.containers
reachability_creator = ReachabilityCreator(containers, policy_parser.network_policies)

reachability_matrix = reachability_creator.create_reachability_matrix()

test = KubesondeTest(reachability_matrix, containers)
test.prepare_test()

test.create_kubesonde_reachability_matrix()
test.show_differences_in_matrices()
