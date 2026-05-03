import yaml

class Container():
    def __init__(self, name, parent_name, parent_kind, labels, namespace, port, services=[], is_maybe=False):
        self.identity = parent_name+"-"+name+"-"+str(port)
        self.name = name
        self.parent_name = parent_name
        self.parent_kind = parent_kind
        self.labels = labels
        self.namespace = namespace
        self.port = port
        self.services = services
        self.is_maybe = is_maybe

class Service():
    def __init__(self, name, namespace, service_type, selector, ports):
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
        self.containers = []
        self.services = []

        parsed_yaml = self.parse_yaml(yaml_path)
        self.find_containers(parsed_yaml)
        self.match_services_and_containers()
    
    def parse_yaml(self, yaml_path):
        with open(yaml_path, "r") as file:
            parsed_yaml = list(yaml.safe_load_all(file))
        return parsed_yaml

    def find_containers(self, parsed_yaml):
        for component in parsed_yaml:
            namespace = component["metadata"].get("namespace") or "default"
            parent_kind = component["kind"]
            if parent_kind == "Pod":
                labels = component["metadata"].get("labels") or {}
                pod_name = component["metadata"]["name"]
                for container in component["spec"]["containers"]:
                    name = container["name"]
                    ports = container.get("ports") or []
                    if len(ports) > 0:
                        for port in container["ports"]:
                            new_container = Container(name, pod_name, parent_kind, labels, namespace, port["containerPort"])
                    else:
                        new_container = Container(name, pod_name, parent_kind, labels, namespace, "")
                    self.containers.append(new_container)
            elif parent_kind == "Deployment" or parent_kind == "StatefulSet" :
                labels = component["spec"]["template"]["metadata"].get("labels") or []
                deployment_name = component["metadata"]["name"]
                for container in component["spec"]["template"]["spec"]["containers"]:
                    name = container["name"]
                    ports = container.get("ports") or []
                    if len(ports) > 0:
                        for port in container.get("ports"):
                            new_container = Container(name, deployment_name, parent_kind, labels, namespace, port["containerPort"])
                    else:
                        new_container = Container(name, deployment_name, parent_kind, labels, namespace, "")
                    self.containers.append(new_container)
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

    def match_services_and_containers(self):
        for service in self.services:
            for container in self.containers:
                is_add = True
                for key, value in service.selector.items():
                    if key not in container.labels or container.labels[key] != value:
                        is_add = False
                if is_add:
                    container.services.append(service)

    def print_containers(self):
        for container in self.containers:
            print("Container")
            print("--------")
            print(f"Identity: {container.identity}\nContainer Name: {container.name}\nPod Name: {container.parent_name}\nLabels: {container.labels}\nNamespace: {container.namespace}\nPort: {container.port}")
            print()
            print("Service")
            print("--------")
            for service in container.services:
                print(f"Name: {service.name}\nNamespace: {service.namespace}\nService Type: {service.service_type}\nSelector: {service.selector}")
                print("Ports")
                print("---")
                for port in service.ports:
                    print(f"Name: {port.name}\nProtocol: {port.protocol}\nPort: {port.port}\nTarget Port: {port.target_port}\nNode Port: {port.node_port}")
            print()
            print()


if __name__ == "__main__":
    a = ContainerDiscoverer("./application/app.yaml")
    a.print_containers()
