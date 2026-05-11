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
                self.real_matrix[source.identity][destination.identity] = 1

    def prepare_test(self):
        subprocess.run(["minikube", "delete"])
        subprocess.run(["minikube", "start", "--cni=cilium", "--cpus=4", "--memory=8192", "--driver=docker"])
        subprocess.run(["kubectl", "apply", "-f", "./application"])
        #TODO: Instead of putting 20 seconds wait, find a wait for waiting all components of application yaml
        time.sleep(20)
        subprocess.run(["kubectl", "apply", "-f", "./network_policies"])
        #Deploy kubesonde
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde.yaml"])
        time.sleep(10)
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde-probes/probe.yaml"])
        
        #Wait for kubesonde
        subprocess.run(["kubectl", "wait", "--namespace", "kubesonde-system", "--for=condition=available", "deployment/kubesonde-controller-manager", "--timeout=240s"], check=True)
        
        pf_process = subprocess.Popen(["kubectl", "--namespace", "kubesonde-system", "port-forward", "deployment.apps/kubesonde-controller-manager", "2709"])
        #Wait for forwarding
        time.sleep(5)

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
        finally:
            pf_process.terminate()

    def create_kubesonde_reachability_matrix(self):
        with open("./kubesonde/output.json", "r") as file:
            output = json.load(file)
            for item in output.get("items", "[]"):
                source = item.get("source", {})
                source_container = self.find_container_by_json(source)
                destination = item.get("destination", {})
                if destination["type"] == "Service":
                    service_name = destination["name"]
                    destination_container = self.find_container_by_service(service_name)
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
            if source["name"].startswith(container.name) and source["namespace"] == container.namespace:
                return container


if __name__ == "__main__":
    kubesonde_test = KubesondeTest({}, {})
    kubesonde_test.prepare_test()
