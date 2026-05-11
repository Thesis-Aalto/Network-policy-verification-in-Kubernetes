import subprocess
import time
import json

class KubesondeTest():
    def __init__(self, expected_matrix):
        self.expected_matrix = expected_matrix
        self.prepare_test()

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

if __name__ == "__main__":
    kubesonde_test = KubesondeTest({})

