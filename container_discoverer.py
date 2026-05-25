import yaml
import os
import sys


class Workload():
    def __init__(self, name, kind, labels, namespace, containers):
        self.name = name
        self.kind = kind
        self.labels = labels
        self.namespace = namespace
        self.containers = containers
        self.services = []
        

class Container():
    def __init__(self, identity, name, port, is_maybe=False):
        self.identity = identity
        self.name = name
        self.port = port
        self.service = []
        self.is_maybe = is_maybe

class Service():
    def __init__(self, name, namespace, service_type, selector, ports):
        self.identity = service_type+"-"+name
        self.name = name
        self.namespace = namespace
        self.service_type = service_type
        self.selector = selector
        self.ports = ports


class ServicePort():
    def __init__(self, name, protocol, port, target_port, node_port):
        self.name = name
        self.protocol = protocol
        self.port = port
        self.target_port = target_port
        self.node_port = node_port

class ContainerDiscoverer():
    def __init__(self, yaml_path):
        self.workloads = []
        self.services = []

        self.parse_yaml(yaml_path)
    
    def parse_yaml(self, yaml_path):
        for file in os.listdir(yaml_path):
            with open(yaml_path+"/"+file, "r") as f:
                parsed_yaml = list(yaml.safe_load_all(f))
                self.find_workloads(parsed_yaml)
                self.match_services_and_workloads()

    def find_workloads(self, parsed_yaml):
        for component in parsed_yaml:
            namespace = component["metadata"].get("namespace") or "default"
            parent_kind = component["kind"]
            if parent_kind == "Pod":
                labels = component["metadata"].get("labels") or {}
                pod_name = component["metadata"]["name"]
                containers = []
                for container in component["spec"]["containers"]:
                    name = container["name"]
                    ports = container.get("ports") or []
                    if len(ports) > 0:
                        for port in container["ports"]:
                            identity = pod_name+"-"+name+"-"+str(port["containerPort"])
                            new_container = Container(identity, name, port["containerPort"])
                    else:
                        identity = pod_name+"-"+name
                        new_container = Container(identity, name, new_workload,  "")
                    containers.append(new_container)
                new_workload = Workload(pod_name, parent_kind, labels, namespace, containers)
                self.workloads.append(new_workload)
            elif parent_kind == "Deployment" or parent_kind == "StatefulSet" or parent_kind == "ReplicaSet" or parent_kind=="Job":
                labels = component.get("spec", {}).get("template", {}).get("metadata", {}).get("labels") or []
                deployment_name = component["metadata"]["name"]
                containers = []
                for container in component["spec"]["template"]["spec"]["containers"]:
                    name = container["name"]
                    ports = container.get("ports") or []
                    if len(ports) > 0:
                        for port in container.get("ports"):
                            identity = deployment_name+"-"+name+"-"+str(port["containerPort"])
                            new_container = Container(identity, name, port["containerPort"])
                    else:
                        identity = deployment_name+"-"+name
                        new_container = Container(identity, name, "")
                    containers.append(new_container)
                new_workload = Workload(deployment_name, parent_kind, labels, namespace, containers)
                self.workloads.append(new_workload)
            elif parent_kind == "Service":
                new_service = self.get_service(component)
                self.services.append(new_service)

    def get_service(self, service):
        name = service["metadata"]["name"]
        namespace = service["metadata"].get("namespace") or "default"
        service_type = service["spec"].get("type") or "ClusterIP"
        selector = service["spec"]["selector"]
        ports = []
        for port in service["spec"]["ports"]:
            port_name = port.get("name") or ""
            protocol = port.get("protocol") or "TCP"
            service_port = port["port"]
            target_port = port.get("targetPort") or service_port
            node_port = port.get("nodePort") or ""
            new_port = ServicePort(port_name, protocol, service_port, target_port, node_port)
            ports.append(new_port)
        new_service = Service(name, namespace, service_type, selector, ports)
        return new_service

    def match_services_and_workloads(self):
        for service in self.services:
            for workload in self.workloads:
                is_add = True
                for key, value in service.selector.items():
                    if key not in workload.labels or workload.labels[key] != value:
                        is_add = False
                if is_add:
                    workload.services.append(service)

    def print_workloads(self):
        for workload in self.workloads:
            print(f"=== WORKLOAD: {workload.name} ===")
            print(f"  Kind:      {workload.kind}")
            print(f"  Namespace: {workload.namespace}")
            print(f"  Labels:    {workload.labels}")
            print()

            print("  Services:")
            if not workload.services:
                print("    (None)")
            for service in workload.services:
                print(f"    - Name:         {service.name}")
                print(f"      Namespace:    {service.namespace}")
                print(f"      Type:         {service.service_type}")
                print(f"      Selector:     {service.selector}")
                
                # Nested Ports
                if service.ports:
                    print("      Ports:")
                    for port in service.ports:
                        port_info = f"Port: {port.port} -> {port.target_port}/{port.protocol}"
                        if port.node_port:
                            port_info += f" (NodePort: {port.node_port})"
                        if port.name:
                            port_info = f"[{port.name}] " + port_info
                        print(f"        * {port_info}")
                print()

            print("  Containers:")
            if not workload.containers:
                print("    (None)")
            for container in workload.containers:
                print(f"    - Name: {container.name}")
                print(f"      Port: {container.port}")
                
            print("\n" + "="*40 + "\n")


if __name__ == "__main__":
    application_folder_path = "./application/aks-store-demo"
    if (len(sys.argv)) == 2:
        application_folder_path = sys.argv[1]
    
    a = ContainerDiscoverer(application_folder_path)
    a.print_workloads()
