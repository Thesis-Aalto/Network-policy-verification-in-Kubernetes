from container_discoverer import ContainerDiscoverer
from policy_parser import PolicyParser
from reachability_creator import ReachabilityCreator
from testing.kubesonde_test import KubesondeTest

import sys

application_folder_path = "./application/aks-store-demo"
policy_folder_path = "./network_policies/example"
if len(sys.argv) > 2:
    application_folder_path = sys.argv[1]
    policy_folder_path = sys.argv[2] 
elif len(sys.argv) > 1:
    application_folder_path = sys.argv[1]

container_discoverer = ContainerDiscoverer(application_folder_path)
policy_parser = PolicyParser(policy_folder_path)

containers = container_discoverer.containers
services = container_discoverer.services
reachability_creator = ReachabilityCreator(services, containers, policy_parser.network_policies)

reachability_matrix = reachability_creator.create_reachability_matrix()

test = KubesondeTest(reachability_matrix, containers)
test.prepare_test()

test.create_kubesonde_reachability_matrix()
test.show_differences_in_matrices()
