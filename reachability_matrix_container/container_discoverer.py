import yaml

class Container():
    def __init__(self, name, pod_deployment_name, labels, namespace, port):
        self.identity = pod_deployment_name+"-"+name+"-"+str(port)
        self.name = name
        self.pod_deployment_name = pod_deployment_name
        self.labels = labels
        self.namespace = namespace
        self.port = port

class ContainerDiscoverer():
    def __init__(self, yaml_path):
        self.containers = []
        parsed_yaml = self.parse_yaml(yaml_path)
        self.find_containers(parsed_yaml)
    
    def parse_yaml(self, yaml_path):
        with open(yaml_path, "r") as file:
            parsed_yaml = list(yaml.safe_load_all(file))
        return parsed_yaml

    def find_containers(self, parsed_yaml):
        for component in parsed_yaml:
            namespace = component["metadata"].get("namespace") or "default"
            if component["kind"] == "Pod":
                labels = component["metadata"].get("labels") or {}
                pod_name = component["metadata"]["name"]
                for container in component["spec"]["containers"]:
                    name = container["name"]
                    for port in container["ports"]:
                        new_container = Container(name, pod_name, labels, namespace, port["containerPort"])
                    self.containers.append(new_container)
            elif component["kind"] == "Deployment":
                labels = component["spec"]["template"]["metadata"].get("labels") or []
                deployment_name = component["metadata"]["name"]
                for container in component["spec"]["template"]["spec"]["containers"]:
                    name = container["name"]
                    ports = container.get("ports") or []
                    if len(ports) > 0:
                        for port in container.get("ports"):
                            new_container = Container(name, deployment_name, labels, namespace, port["containerPort"])
                    else:
                        new_container = Container(name, deployment_name, labels, namespace, "")
                    self.containers.append(new_container)

    def print_containers(self):
        for container in self.containers:
            print(f"Identity:{container.identity}\nContainer Name: {container.name}\nPod Name: {container.pod_deployment_name}\nLabels: {container.labels}\nNamespace: {container.namespace}\nPort: {container.port}")
            print()
                


if __name__ == "__main__":
    a = ContainerDiscoverer("./application/app.yaml")
    a.print_containers()
