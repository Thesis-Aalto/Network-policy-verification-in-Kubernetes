# Kubernetes Network Policy Verification Thesis Project

## Requirments

To run the project, you need to have python 3.10 or higher. If you want to try kubsonde_test, you need to install minikube.

## Description of Application
  There are 4 parts of the application as ContainerDiscoverer, PolicyParser, ReachabilityCreator and KubeSondeTest. ContainerDiscoverer parses the given application yaml file and creates Container object that will be used for matching with policies in ReachabilityCreator. PolicyParser parses given Kubernetes network policies. ReachabilityCreator finds source and target containers for a given network policy and update ingress and egress matrices. At the end, it create reachability matrix from those matrices

## How to run
  You can specify you testbed as folder under the **application** folder. There are already 2 different testbeds specified as aks-store-demo and istio-bookinfo .After that you can define you network policies as folder under **network_policies**. deny-all policy is defined as an example .
  
  You can run each component separately. Each component will show its result on the terminal after the end of the program. Components will use aks-store-demo as application folder and example as policy folder on default. Here are the steps to run the components:
  1. Run `pip install -r requirements.txt` command
  2. For PolicyParser
     1. You can directly run the PolicyParser by this command `python3 policy_parser.py`. 
     2. If you have different network policy folder, you can specify it as command line argument like this `python3 policy_parser.py <relative path of policy folder>`. It will show you the content of parsed network policies.
  3. For ContainerDiscoverer
     1. You can directly run the ContainerDiscoverer by this command `python3 container_discoverer.py`. 
     2. If you have different application folder, you can specify is as command line argument list this `python3 container_discoverer.py <relative path of application folder>`.
  4. For ReachabilityCreator
     1. You can run ReachabilityCreator by this command `python3 reachability_creator.py`. It automatically uses ContainerDiscoverer and PolicyParser
     2. If you want to specify your own application folder or network policy folder you can run `python3 reachability_creator.py <relative path of application folder> <relative path of policy folder>`
  5. For KubesondeTest
     1. First of all you need to have minikube installed to run this command
     2. You can run KubesondeTest by this command `python3 main.py`
     3. You can specify application folder and policy folder as command line argument `python3 main.py <relative path of application folder> <relative path of policy folder>`

  