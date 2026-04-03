import hashlib
import itertools
import os
from datetime import datetime, timezone

import yaml


class NetworkCreatorClass:
    def __init__(
        self,
        inventory_yaml_path="./testbeds/aks-store-demo/aks-store-all-in-one.yaml",
        output_dir="generated-networkpolicies",
        include_deny_all=True,
        include_ingress=True,
        include_egress=True,
        max_destinations_per_policy=None,
        namespace_overrides=None,
    ):
        self.inventory_yaml_path = inventory_yaml_path
        self.output_dir = output_dir
        self.include_deny_all = bool(include_deny_all)
        self.include_ingress = bool(include_ingress)
        self.include_egress = bool(include_egress)
        self.max_destinations_per_policy = max_destinations_per_policy
        self.namespace_overrides = namespace_overrides or {}

        self._ensure_output_dir()
        self.inventory = self._load_inventory()
        self._run_stamp = None

    def create_policies_for_all_testbeds(self):
        results = {}
        available = set((self.inventory.get("testbeds") or {}).keys())
        preferred = ["aks-store-demo", "istio-bookinfo"]
        ordered = [t for t in preferred if t in available] + sorted([t for t in available if t not in preferred])

        for testbed in ordered:
            results[testbed] = self.create_policies_for_testbed(testbed)
        return results

    def create_policies_for_testbed(self, testbed):
        self._run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        namespaces = self._get_testbed_namespaces(testbed)
        workloads = self._workloads_from_inventory(testbed, namespaces)

        written = []
        if self.include_deny_all:
            for ns in namespaces:
                p = self._deny_all_policy(ns, name=f"deny-all-{ns}")
                written.extend(self._write_policy_yaml(testbed, ns, p))

        written.extend(self._generate_allow_policies(testbed, workloads))
        return {
            "testbed": testbed,
            "namespaces": namespaces,
            "workloads": sorted(list({w["id"] for w in workloads})),
            "written_files": written,
        }

    def _load_inventory(self):
        if not os.path.exists(self.inventory_yaml_path):
            raise RuntimeError(
                f"Inventory YAML not found at '{self.inventory_yaml_path}'."
            )
        with open(self.inventory_yaml_path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        merged = {"testbeds": {}}
        inferred_workloads = []
        for doc in docs:
            if not doc:
                continue
            if not isinstance(doc, dict):
                raise RuntimeError("Each YAML document must be a mapping/object.")

            inferred = self._extract_workload_from_k8s_manifest(doc)
            if inferred:
                inferred_workloads.append(inferred)

            tb = doc.get("testbeds")
            if tb is None:
                continue
            if not isinstance(tb, dict):
                raise RuntimeError("Inventory YAML key 'testbeds' must be a mapping/object.")

            for name, spec in tb.items():
                if name in merged["testbeds"]:
                    raise RuntimeError(f"Duplicate testbed '{name}' across YAML documents.")
                merged["testbeds"][name] = spec

        if not merged["testbeds"] and inferred_workloads:
            merged["testbeds"] = self._default_testbeds_from_inferred(inferred_workloads)

        if inferred_workloads:
            self._merge_inferred_workloads(merged, inferred_workloads)

        if not merged["testbeds"]:
            raise RuntimeError("Inventory YAML must define at least one testbed under 'testbeds:'.")

        return merged

    def _extract_workload_from_k8s_manifest(self, doc):
        kind = doc.get("kind")
        if kind not in {"Deployment", "StatefulSet"}:
            return None

        metadata = doc.get("metadata") or {}
        name = metadata.get("name")
        if not name:
            return None

        namespace = metadata.get("namespace") or "default"
        spec = doc.get("spec") or {}
        selector = ((spec.get("selector") or {}).get("matchLabels")) or {}
        if not selector:
            return None

        template = (spec.get("template") or {}).get("spec") or {}
        containers = template.get("containers") or []
        ports = []
        for c in containers:
            for p in (c.get("ports") or []):
                cp = p.get("containerPort")
                if cp is None:
                    continue
                ports.append(int(cp))

        expanded = []
        for port in sorted(set(ports)):
            expanded.append({"port": port, "protocol": "TCP"})
            expanded.append({"port": port, "protocol": "UDP"})

        return {
            "name": name,
            "namespace": namespace,
            "selector": selector,
            "ports": expanded,
        }

    def _default_testbeds_from_inferred(self, inferred_workloads):
        by_ns = {}
        for w in inferred_workloads:
            by_ns.setdefault(w["namespace"], []).append(w)

        testbeds = {}
        for ns in sorted(by_ns.keys()):
            if ns == "aks-store-demo":
                tb_name = "aks-store-demo"
            elif ns == "default":
                tb_name = "istio-bookinfo"
            else:
                tb_name = f"ns-{ns}"

            testbeds[tb_name] = {
                "namespaces": [ns],
                "workloads": [],
            }
        return testbeds

    def _merge_inferred_workloads(self, merged, inferred_workloads):
        ns_to_tb = {}
        for tb_name, spec in (merged.get("testbeds") or {}).items():
            for ns in (spec or {}).get("namespaces") or []:
                ns_to_tb[ns] = tb_name

        for w in inferred_workloads:
            ns = w["namespace"]
            tb_name = ns_to_tb.get(ns)
            if not tb_name:
                continue

            spec = merged["testbeds"].setdefault(tb_name, {"namespaces": [ns], "workloads": []})
            spec.setdefault("namespaces", [])
            if ns not in spec["namespaces"]:
                spec["namespaces"].append(ns)

            spec.setdefault("workloads", [])
            if any(x.get("name") == w["name"] and x.get("namespace") == w["namespace"] for x in spec["workloads"]):
                continue
            spec["workloads"].append(w)

    def _ensure_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def _get_testbed_namespaces(self, testbed):
        if testbed in self.namespace_overrides:
            v = self.namespace_overrides[testbed]
            if isinstance(v, str):
                return [v]
            return list(v)

        tb = (self.inventory.get("testbeds") or {}).get(testbed) or {}
        inv_namespaces = tb.get("namespaces") or []
        if inv_namespaces:
            return list(inv_namespaces)
        raise ValueError(f"Unknown testbed: {testbed}")

    def _workloads_from_inventory(self, testbed, namespaces):
        tb = (self.inventory.get("testbeds") or {}).get(testbed)
        if not tb:
            raise RuntimeError(f"Testbed '{testbed}' not found in inventory YAML.")

        inv_workloads = tb.get("workloads") or []
        workloads = []

        for w in inv_workloads:
            ns = w.get("namespace")
            if ns not in namespaces:
                continue

            selector = w.get("selector") or {}
            if not selector:
                raise RuntimeError(
                    f"Workload '{w.get('name')}' in '{testbed}' missing selector."
                )

            ports = self._normalize_ports(w.get("ports") or [])
            workload_id = self._workload_id(ns, selector, name=w.get("name"))

            workloads.append(
                {
                    "id": workload_id,
                    "name": w.get("name") or workload_id,
                    "namespace": ns,
                    "selector": selector,
                    "ports": ports,
                }
            )

        uniq = {}
        for w in workloads:
            uniq[w["id"]] = self._merge_workloads(uniq.get(w["id"]), w)
        return list(uniq.values())

    def _merge_workloads(self, a, b):
        if not a:
            return b
        merged = {
            "id": a["id"],
            "name": a.get("name") or b.get("name"),
            "namespace": a["namespace"],
            "selector": a["selector"],
            "ports": self._merge_ports(a.get("ports", []), b.get("ports", [])),
        }
        return merged

    def _merge_ports(self, a_ports, b_ports):
        seen = set()
        merged = []
        for p in (a_ports or []) + (b_ports or []):
            key = (p.get("port"), (p.get("protocol") or "TCP").upper())
            if key in seen:
                continue
            seen.add(key)
            merged.append({"port": int(p.get("port")), "protocol": (p.get("protocol") or "TCP").upper()})
        return sorted(merged, key=lambda x: (x.get("protocol") or "", x.get("port") or 0))

    def _normalize_ports(self, ports):
        norm = []
        for p in ports or []:
            if p is None:
                continue
            port = p.get("port")
            if port is None:
                continue
            proto = (p.get("protocol") or "TCP").upper()
            norm.append({"port": int(port), "protocol": proto})
        return self._merge_ports([], norm)

    def _generate_allow_policies(self, testbed, workloads):
        written = []
        policies_emitted = 0

        by_ns = {}
        for w in workloads:
            by_ns.setdefault(w["namespace"], []).append(w)

        for ns, ns_workloads in by_ns.items():
            for src in ns_workloads:
                destinations = [d for d in ns_workloads if d["id"] != src["id"]]
                if not destinations:
                    continue

                for subset in self._all_non_empty_subsets(destinations):
                    if self.max_destinations_per_policy is not None and len(subset) > int(
                        self.max_destinations_per_policy
                    ):
                        continue

                    dest_selectors = [d["selector"] for d in subset]
                    combined_ports = self._union_ports([d.get("ports", []) for d in subset])

                    policy_name = self._policy_name(
                        prefix="allow",
                        src=src,
                        dests=subset,
                        direction=("ingress" if self.include_ingress else "")
                        + ("-egress" if self.include_egress else ""),
                    )

                    if self.include_ingress:
                        for dest in subset:
                            p_ing = self._allow_ingress_policy(
                                namespace=ns,
                                name=self._ingress_policy_name(policy_name, dest),
                                dest_selector=dest["selector"],
                                from_selector=src["selector"],
                                ports=combined_ports,
                            )
                            written.extend(self._write_policy_yaml(testbed, ns, p_ing))
                            policies_emitted += 1
                            if policies_emitted % 500 == 0:
                                print(
                                    f"[{testbed}/{ns}] generated {policies_emitted} policies...",
                                    flush=True,
                                )

                    if self.include_egress:
                        p_eg = self._allow_egress_policy(
                            namespace=ns,
                            name=policy_name + "-eg",
                            src_selector=src["selector"],
                            to_selectors=dest_selectors,
                            ports=combined_ports,
                        )
                        written.extend(self._write_policy_yaml(testbed, ns, p_eg))
                        policies_emitted += 1
                        if policies_emitted % 500 == 0:
                            print(
                                f"[{testbed}/{ns}] generated {policies_emitted} policies...",
                                flush=True,
                            )

        return written

    def _union_ports(self, ports_lists):
        merged = []
        seen = set()
        for plist in ports_lists:
            for p in plist or []:
                key = (p.get("port"), (p.get("protocol") or "").upper())
                if key in seen:
                    continue
                seen.add(key)
                merged.append({"port": p.get("port"), "protocol": (p.get("protocol") or "TCP").upper()})
        return sorted(merged, key=lambda x: (x.get("protocol") or "", x.get("port") or 0))

    def _all_non_empty_subsets(self, items):
        items = list(items)
        for r in range(1, len(items) + 1):
            for subset in itertools.combinations(items, r):
                yield list(subset)

    def _workload_id(self, namespace, selector, name=None):
        if name:
            return f"{namespace}:{name}"
        key = ",".join([f"{k}={selector[k]}" for k in sorted(selector.keys())])
        return f"{namespace}:{key}"

    def _policy_name(self, prefix, src, dests, direction):
        s = src["id"]
        d = ",".join([x["id"] for x in dests])
        raw = f"{prefix}|{direction}|{s}|{d}".encode("utf-8")
        h = hashlib.sha256(raw).hexdigest()[:10]
        base = f"{prefix}-{h}"
        return base

    def _deny_all_policy(self, namespace, name):
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

    def _ingress_policy_name(self, base, dest):
        raw = f"{base}|dest|{dest['id']}".encode("utf-8")
        h = hashlib.sha256(raw).hexdigest()[:8]
        return f"{base}-ing-{h}"

    def _allow_ingress_policy(self, namespace, name, dest_selector, from_selector, ports):
        ingress_rule = {"from": [{"podSelector": {"matchLabels": from_selector}}]}
        if ports:
            ingress_rule["ports"] = [{"protocol": p["protocol"], "port": p["port"]} for p in ports]

        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": dest_selector},
                "policyTypes": ["Ingress"],
                "ingress": [ingress_rule],
            },
        }

    def _allow_egress_policy(self, namespace, name, src_selector, to_selectors, ports):
        to_rules = [{"podSelector": {"matchLabels": s}} for s in to_selectors]
        egress_rule = {"to": to_rules}
        if ports:
            egress_rule["ports"] = [{"protocol": p["protocol"], "port": p["port"]} for p in ports]

        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": src_selector},
                "policyTypes": ["Egress"],
                "egress": [egress_rule],
            },
        }

    def _write_policy_yaml(self, testbed, namespace, policy_obj):
        stamp = self._run_stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = os.path.join(self.output_dir, testbed, namespace)
        os.makedirs(out_dir, exist_ok=True)

        name = policy_obj.get("metadata", {}).get("name", "policy")
        path = os.path.join(out_dir, f"{name}-{stamp}.yaml")

        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(policy_obj, f, sort_keys=False)
        return [path]


def main():
    creator = NetworkCreatorClass()
    creator.create_policies_for_all_testbeds()


if __name__ == "__main__":
    main()

