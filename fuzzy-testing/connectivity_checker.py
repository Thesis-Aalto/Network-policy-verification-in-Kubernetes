import csv
import datetime as dt
import os
import subprocess
from typing import Dict, List, Optional, Tuple


class ConnectivityChecker:
    def __init__(self, policy_path, testbed_path, workloads, namespace = "default", output_csv_path = "reports/connectivity.csv", connect_timeout_s = 6):
        self.policy_path = policy_path
        self.testbed_path = testbed_path
        self.workloads = workloads
        self.namespace = namespace
        self.output_csv_path = output_csv_path
        self.connect_timeout_s = connect_timeout_s
        self.all_destinations: List[str] = []
    
    def start(self):
        self._get_pod_ips_by_label()
        self._apply_policy_and_check_connections()

    def _get_pod_ips_by_label(self, namespace="default"):
        for name, value in self.workloads.items():
            self.all_destinations.append(name)
            label_selector = ""
            for key, value in value["pod_labels"].items():
                label_selector+=key+"="+value+","
            label_selector = label_selector[:-1]
            pod_name = subprocess.run(["kubectl", "get", "pods", "-n", self.namespace, "-l", label_selector, "-o", "jsonpath={.items[0].metadata.name}"], capture_output=True, text=True).stdout.strip()
            pod_ip = subprocess.run(["kubectl", "get", "pods", "-n", self.namespace, "-l", label_selector, "-o", "jsonpath={.items[0].status.podIP}"], capture_output=True, text=True).stdout.strip()
            self.workloads[name]["pod_name"] = pod_name
            self.workloads[name]["pod_ip"] = pod_ip

    def _apply_policy_and_check_connections(self):
        self._ensure_csv_header()
        for folder in os.listdir(self.policy_path):
            if folder == "default":
                subprocess.run(["kubectl", "apply", "-f", self.policy_path+"/"+folder])
            else:
                for file in os.listdir(self.policy_path+"/"+folder):
                    subprocess.run(["kubectl", "apply", "-f", self.policy_path+"/"+folder+"/"+file])
                    protocol = file.split("-")[0]
                    self.check_connectivity(folder, protocol, applied_policy=file)
                    subprocess.run(["kubectl", "delete", "-f", self.policy_path+"/"+folder+"/"+file])
    
    def check_connectivity(self, source, protocol, applied_policy):
        source_pod = self.workloads[source].get("pod_name")
        source_ip = self.workloads[source].get("pod_ip")
        source_ports = self._get_ports_for_workload(source)

        if not source_pod or not source_ip or not source_ports:
            self._append_csv_row(
                applied_policy=applied_policy,
                direction=protocol,
                src=source,
                dst="*",
                ok=False,
                message=f"Missing source pod/ip/ports for workload '{source}'",
            )
            return

        for destination in self.all_destinations:
            if destination == source:
                continue
            destination_pod = self.workloads[destination].get("pod_name")
            destination_ip = self.workloads[destination].get("pod_ip")

            if protocol == "ingress":
                # FROM destination -> TO source
                if not destination_pod:
                    self._append_csv_row(
                        applied_policy=applied_policy,
                        direction="ingress",
                        src=destination,
                        dst=source,
                        ok=False,
                        message=f"Missing destination pod name for workload '{destination}'",
                    )
                    continue
                for port in source_ports:
                    ok, msg = self._probe_from_pod(src_pod=destination_pod, dst_ip=source_ip, port=port)
                    self._append_csv_row(
                        applied_policy=applied_policy,
                        direction="ingress",
                        src=destination,
                        dst=source,
                        ok=ok,
                        message=msg,
                        port=port,
                        dst_ip=source_ip,
                    )
            else:
                # egress: FROM source -> TO destination
                if not destination_ip:
                    self._append_csv_row(
                        applied_policy=applied_policy,
                        direction="egress",
                        src=source,
                        dst=destination,
                        ok=False,
                        message=f"Missing destination IP for workload '{destination}'",
                    )
                    continue
                dst_ports = self._get_ports_for_workload(destination)
                if not dst_ports:
                    self._append_csv_row(
                        applied_policy=applied_policy,
                        direction="egress",
                        src=source,
                        dst=destination,
                        ok=False,
                        message=f"No known destination ports for workload '{destination}'",
                    )
                    continue
                for port in dst_ports:
                    ok, msg = self._probe_from_pod(src_pod=source_pod, dst_ip=destination_ip, port=port)
                    self._append_csv_row(
                        applied_policy=applied_policy,
                        direction="egress",
                        src=source,
                        dst=destination,
                        ok=ok,
                        message=msg,
                        port=port,
                        dst_ip=destination_ip,
                    )

    def _get_ports_for_workload(self, workload_name):
        wl = self.workloads.get(workload_name) or {}
        svc = wl.get("service") or {}
        ports_yaml = svc.get("ports") or []
        out: List[int] = []
        for p in ports_yaml:
            try:
                out.append(int(p.get("port")))
            except Exception:
                continue
        return out

    def _probe_from_pod(self, src_pod, dst_ip, port):
        script = f"""
            set -eu
            IP="{dst_ip}"
            PORT="{port}"
            if command -v curl >/dev/null 2>&1; then
            curl -v -m {int(self.connect_timeout_s)} "http://$IP:$PORT/" -o /dev/null
            exit $?
            fi
            if command -v wget >/dev/null 2>&1; then
            wget -T {int(self.connect_timeout_s)} -O /dev/null "http://$IP:$PORT/"
            exit $?
            fi
            if command -v nc >/dev/null 2>&1; then
            nc -zvw {int(self.connect_timeout_s)} "$IP" "$PORT"
            exit $?
            fi
            echo "No curl/wget/nc available in pod" >&2
            exit 2
            """.strip()
        p = subprocess.run(
            ["kubectl", "exec", "-n", self.namespace, src_pod, "--", "sh", "-c", script],
            capture_output=True,
            text=True,
        )
        ok = p.returncode == 0
        msg = ((p.stdout or "") + (p.stderr or "")).strip()
        return ok, msg or ("ok" if ok else "failed")

    def _ensure_csv_header(self):
        os.makedirs(os.path.dirname(self.output_csv_path) or ".", exist_ok=True)
        if os.path.exists(self.output_csv_path) and os.path.getsize(self.output_csv_path) > 0:
            return
        with open(self.output_csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self._csv_fields())
            w.writeheader()

    def _append_csv_row(self, applied_policy, direction, src, dst, ok, message, port= None, dst_ip=None):
        with open(self.output_csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self._csv_fields())
            w.writerow(
                {
                    "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "applied_policy": applied_policy,
                    "direction": direction,
                    "namespace": self.namespace,
                    "src_workload": src,
                    "dst_workload": dst,
                    "dst_ip": dst_ip or "",
                    "dst_port": "" if port is None else port,
                    "connection_possible": "yes" if ok else "no",
                    "message": message,
                }
            )

    def _csv_fields(self):
        return [
            "timestamp_utc",
            "applied_policy",
            "direction",
            "namespace",
            "src_workload",
            "dst_workload",
            "dst_ip",
            "dst_port",
            "connection_possible",
            "message",
        ]



    






