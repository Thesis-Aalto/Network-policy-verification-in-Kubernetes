import subprocess
import time

class KubesondeTest():
    def __init__(self, expected_matrix):
        self.expected_matrix = expected_matrix
        self.prepare_test()

    def prepare_test(self):
        subprocess.run(["minikube", "delete"])
        subprocess.run(["minikube", "start", "--cni=cilium"])
        subprocess.run(["kubectl", "apply", "-f", "./application"])
        subprocess.run(["kubectl", "apply", "-f", "./network_policies"])
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde.yaml"])
        subprocess.run(["kubectl", "apply", "-f", "./kubesonde/kubesonde-probes/probe.yaml"])
        subprocess.run(["kubectl", "wait", "--namespace", "kubesonde-system", "--for=condition=available", "deployment/kubesonde-controller-manager", "--timeout=120s"], check=True)
        
        pf_process = subprocess.Popen(["kubectl", "--namespace", "kubesonde-system", "port-forward", "deployment.apps/kubesonde-controller-manager", "2709:2709"])
        
        time.sleep(3)
        
        try:
            print("--- Fetching Probes ---")
            # Use Python to handle the file writing to avoid shell redirection issues
            with open("output.json", "w") as f:
                subprocess.run(["curl", "-s", "localhost:2709/probes"], stdout=f, check=True)
            print("Successfully saved output.json")
        finally:
            # Terminate the port-forward process when done
            pf_process.terminate()

if __name__ == "__main__":
    kubesonde_test = KubesondeTest({})
    kubesonde_test.prepare_test()

