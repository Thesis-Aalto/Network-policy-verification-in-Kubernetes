# Reachability Modeling for Kubernetes Network Policies

Offline control-plane verification of Kubernetes and Cilium network policies. The tool analyses application and policy YAML manifests (no running cluster required), builds a reachability matrix of allowed and denied communication, answers connectivity queries, and compares policy sets for semantic equivalence or redundancy.

## Requirements

- Python 3.10 or newer
- Dependencies: `pip install -r requirements.txt` (`PyYAML`, `pandas`)
- Optional (Kubesonde comparison only): [Minikube](https://minikube.sigs.k8s.io/) and a working cluster

## Components

| Component | File | Role |
| --- | --- | --- |
| Workload Discoverer | `container_discoverer.py` | Parses application manifests; extracts namespaces, workloads, services, labels, and ports |
| Policy Parser | `policy_parser.py` | Parses Kubernetes `NetworkPolicy` and Cilium CRDs into a common internal representation |
| Reachability Creator | `reachability_creator.py` | Builds ingress/egress matrices, combines them into a reachability matrix, and resolves connectivity queries with priority tiers |
| Policy Simplifier | `policy_simplifier.py` | Compares two policy sets over the same topology (equivalence / redundancy) |
| Kubesonde test | `testing/kubesonde_test.py` / `main.py` | Optional runtime comparison against Kubesonde (requires Minikube) |

Supported policy features include pod and namespace selectors, `ipBlock`/CIDR rules, ingress and egress, ports and port ranges, Cilium explicit deny rules, and Cilium cluster-wide policies.

## Project layout

```
.
├── container_discoverer.py
├── policy_parser.py
├── reachability_creator.py
├── policy_simplifier.py
├── main.py                          # optional Kubesonde workflow
├── requirements.txt
└── testing/
    ├── application/                 # aks-store-demo, istio-bookinfo
    ├── network_policies/            # per-testbed policy scenarios
    ├── expected_result/             # CSV oracles for matrix tests
    ├── query-cases/                 # JSON oracles for connectivity queries
    ├── comparison-cases/            # policy-pair cases for the simplifier
    ├── scenario_test.py             # correctness suite
    ├── performance_test.py          # scalability benchmarks
    └── kubesonde_test.py
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run individual components

Defaults in some scripts still point at `./application` and `./network_policies`. Prefer the paths under `testing/`:

```bash
# Workload discovery
python3 container_discoverer.py testing/application/aks-store-demo

# Policy parsing (file or directory)
python3 policy_parser.py testing/network_policies/aks-store-demo/egress.yaml

# Reachability matrix
python3 reachability_creator.py \
  testing/application/aks-store-demo \
  testing/network_policies/aks-store-demo/egress.yaml

# Compare two policy sets
python3 policy_simplifier.py \
  testing/application/aks-store-demo \
  testing/comparison-cases/aks-store-demo/non-equivalent/policies-a.yaml \
  testing/comparison-cases/aks-store-demo/non-equivalent/policies-b.yaml
```

### Correctness evaluation

Runs matrix, connectivity-query, and policy-simplifier tests against manually annotated oracles for both testbeds:

```bash
python3 testing/scenario_test.py
```

Exits with status `1` if any case fails.

### Performance evaluation

Benchmarks matrix construction, query latency, and policy comparison under synthetic policy loads:

```bash
python3 testing/performance_test.py
python3 testing/performance_test.py --testbed aks-store-demo --policy-counts 10 25 50 100
```

### Optional Kubesonde comparison

Requires Minikube. Applies manifests, probes runtime reachability, and compares with the offline matrix:

```bash
python3 main.py testing/application/aks-store-demo <policy-path>
```

## Testbeds

- **aks-store-demo** — Microsoft sample store, adapted to `frontend-ns`, `backend-ns`, and `database-ns`
- **istio-bookinfo** — Istio Bookinfo, likewise split across namespaces

Policy scenarios cover Kubernetes and Cilium allow/deny cases, selectors, ports, CIDRs, cluster-wide rules, and comparison cases (`k8s-cilium-equivalent`, `non-equivalent`, `superset-redundant`).

## Thesis

This repository accompanies the MSc thesis *Reachability Modeling for Kubernetes Network Policies* (SECCLO / Aalto University & EURECOM).
