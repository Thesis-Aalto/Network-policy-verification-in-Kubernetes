import subprocess
import time
import json

class KubesondeTest():
    def __init__(self, expected_matrix, containers):
        self.expected_matrix = expected_matrix
        self.containers = containers
        self.real_matrix = {}
        self.fill_real_matrix()

    def fill_real_matrix(self):
        for source in self.containers:
            self.real_matrix[source.identity] = {}
            for destination in self.containers:
                self.real_matrix[source.identity][destination.identity] = 0

    def prepare_test(self):
        subprocess.run(["minikube", "delete"])
        subprocess.run(["minikube", "start", "--cni=cilium", "--driver=docker"])
        subprocess.run(["kubectl", "apply", "-f", "./application"])
        #TODO: Instead of putting 30 seconds wait, find a wait for waiting all components of application yaml
        time.sleep(30)
        subprocess.run(["kubectl", "apply", "-f", "./network_policies"])
        #Deploy kubesonde
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde.yaml"])
        time.sleep(10)
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde-probes/probe.yaml"])
        
        #Wait for kubesonde
        subprocess.run(["kubectl", "wait", "--namespace", "kubesonde-system", "--for=condition=available", "deployment/kubesonde-controller-manager", "--timeout=240s"], check=True)
        
        pf_process = subprocess.Popen(["kubectl", "--namespace", "kubesonde-system", "port-forward", "deployment.apps/kubesonde-controller-manager", "2709"])
        #Wait for forwarding
        time.sleep(150)

        try:
            print("--- Fetching Probes ---")
            is_success = False
            while not is_success:
                with open("./kubesonde/output.json", "w") as f:
                    subprocess.run(["curl", "-s", "localhost:2709/probes"], stdout=f, check=True)
                with open("./kubesonde/output.json", "r") as file:
                    output = json.load(file)
                    if len(output.get("items", [])) != 0:
                        is_success = True
                    else:
                        print("Fetching failed. Trying again")
                        time.sleep(3)
            print("Successfully saved output.json")
            subprocess.run(["minikube", "delete"])
        finally:
            pf_process.terminate()

    def create_kubesonde_reachability_matrix(self):
        with open("./kubesonde/output.json", "r") as file:
            output = json.load(file)
            for item in output.get("items", "[]"):
                source = item.get("source", {})
                source_container = self.find_container_by_json(source)
                destination = item.get("destination", {})
                destination_container = None
                if destination["type"] == "Service":
                    service_name = destination["name"]
                    destination_container = self.find_container_by_service(service_name)
                elif destination["type"] == "Pod":
                    destination_container = self.find_container_by_json(destination)
                if source_container != None and destination_container != None:
                    if item.get("resultingAction") == "Allow":
                        self.real_matrix[source_container.identity][destination_container.identity] = 1
                    else:
                        self.real_matrix[source_container.identity][destination_container.identity] = 0


    def find_container_by_service(self, service_name):
        for container in self.containers:
            for service in container.services:
                if service.name == service_name:
                    return container
        return None
    
    def find_container_by_json(self, source):
        for container in self.containers:
            if source["name"].startswith(container.parent_name) and source["namespace"] == container.namespace:
                return container

    def show_differences_in_matrices(self):
        print("Kubesonde Matrix")
        print(self.real_matrix)
        print()
        print("Matrix of Reachability Matrix Creator")
        print(self.expected_matrix)
        print()
        print("Differences")
        for source_container in self.containers:
            for target_container in self.containers:
                if self.real_matrix[source_container.identity][target_container.identity] != self.expected_matrix[source_container.identity][target_container.identity]:
                    print(f"KUBESONDE --> From {source_container.identity} to {target_container.identity} is {self.real_matrix[source_container.identity][target_container.identity]}")
                    print(f"REACHABILITY_CREATOR --> From {source_container.identity} to {target_container.identity} is {self.expected_matrix[source_container.identity][target_container.identity]}")
                    print()


if __name__ == "__main__":
    kubesonde_test = KubesondeTest({}, {})
    kubesonde_test.prepare_test()
