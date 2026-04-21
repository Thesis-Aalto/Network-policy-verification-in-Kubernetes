import yaml

class Container():
    def __init__(self, name, pod_name, labels, namespace, ports):
        self.identity = pod_name+"-"+name
        self.name = name
        self.pod_name = pod_name
        self.labels = labels
        self.namespace = namespace
        self.ports = ports

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
                    ports = []
                    name = container["name"]
                    for port in container["ports"]:
                        ports.append(port["containerPort"])
                    new_container = Container(name, pod_name, labels, namespace, ports)
                    self.containers.append(new_container)

    def print_containers(self):
        for container in self.containers:
            print(f"Container Name: {container.name}\nPod Name: {container.pod_name}\nLabels: {container.labels}\nNamespace: {container.namespace}\nPorts")
            for port in container.ports:
                print(f"Port: {port}")
            print()
                


if __name__ == "__main__":
    a = ContainerDiscoverer("./application/app.yaml")
    a.print_containers()
