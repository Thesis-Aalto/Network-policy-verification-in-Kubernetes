# Kubernetes policy verification testbed

This repository will host a Kubernetes policy verification testbed application that respects the specifications provided in this file. 


## Sample app: Istio Bookinfo 

At first you will use the [Istio Bookinfo App](https://istio.io/latest/docs/examples/bookinfo/) as a testbed application for the model. 

Source code is available [here](https://github.com/istio/istio/blob/master/samples/bookinfo/README.md).

![Istio](./istio.png)

## Goals

This thesis project has several goals that will be detailed in this section. However, we will start the project with a focus on L3/L4 policies only. 


### Where to start

Read [Kubernetes documentation](https://kubernetes.io/docs/home/). Focus specifically on:

- Network policies
- Namespaces
- Services
- Pods
- CIDR blocks

[Cilium](https://cilium.io/)

> [!IMPORTANT]
> Read the research papers attached to the proposal.


The model should produce a reachability graph in which each edge may have labels: `yes`/`no`/`allowed`

### First goal: Compute basic reachability

Using the provided bookinfo app, build a connectivity model of the system which allows us to know if two endpoints are reachable.

> [!IMPORTANT]
> An endpoint is a Pod, a Service in the cluster, or a CIDR block. For now let's not worry about domain names. 

At the end of this part, we should know which endpoints are reachable.

#### Example 1

In the basic bookinfo app every endpoint is reachable by every other endpoint. This is because of how networking works in Kuberntes and thus if no policies are applied, all endpoints can reach each other.

#### Example 2

If we add a `default-deny` policy, the reachability graph should be empty. 

```yaml
# default-deny.yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  ingress: []
```

#### Example 3

In this example we allow details service to communicate with the reviews service.

```yaml
# details-to-reviews.yaml 
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-details-to-reviews
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: reviews
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: details
    ports:
    - protocol: TCP
      port: 9080
```

If no other policy exists in the default namespace or if `default-deny` is applied then the reachability graph should contain **only one** edge. 


### Second goal:  Reachability with conflicting network policies
The goal is to model the system taking into account network policy conflicts and signal those inconsistencies. 
For example:
- Superset: a network policy is redundant because the connections are already allowed or denied by another network policy.
- Partial evaluation: there is missing information on whenever the connection can happen.
- Overlap: some connections are allowed by different network policies.

To calculate the reachiability, the model should take into account the additive nature of the policies.

#### Example 4 policy superset.
The model needs to take into account how Kubernetes resolves policies that apply to the same endpoints.  

In this case we are looking at two policies that specify different connectivity between the same endpoints. 


```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-details-to-reviews-9080
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: reviews
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: details
    ports:
    - protocol: TCP
      port: 9080
```

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-details-to-reviews-all-ports
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: reviews
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: details

```

The first policy allows access from details to reviews to a single port, meanwhile the second policy allows all ports. One rule is a superset of another. The model should report the redundancy.


#### Example 5 partial evaluation
A partial evaluation is a case where just by looking at the configuration it is not possible to ensure if the connection can happen.

Given the following yaml: 
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-details-to-reviews-9080
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: reviews
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: details
    ports:
    - protocol: TCP
      port: 9080
    - protocol: TCP
      port: 8080
```

If there is no service listening on port 8080 this is a case of partial evaluation. The model should answer with `allowed` and signal the partial evaluation.




### Goal 3: policy comparison
The goal is to compare how the model changes (or the model output) when provided with different network policies.  
These can be used to compare if two policies are the same or not.

> [!WARNING]
> For now it is enough to support Kubernetes NetworkPolicies and CiliumNetworkPolicies. 

#### Example 6 Comparison
Given these two network policies:

NetworkPolicy:
```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-ingress-lockdown-https
  namespace: default
spec:
  podSelector:
    matchLabels:
      istio: ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 445

```

CiliumNetworkPolicy:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: istio-ingress-lockdown-https
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      istio: ingress

  ingress:
  - toPorts:
    - ports:
      - port: "445"
        protocol: TCP
```
The main idea is to give two policies to the model and the model returns true/false if they are the same. 


### Goal 4: Policy Translation

On top of the preivous goals, we can have a translation script that translates one policy from one format to another. It can possiblly be a different tool, not the model itself. 

Policy translation should be done in such a way that the input is translated into a custom model schema and then from that is converted to the output format.

```
Input <--> Model <--> Output
```

So there should be a separate translation step from policy to model. Then we should check that the model translates back to the same original input model. 

#### Example 7 Translation
Given this network policy:

CiliumNetworkPolicy:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: istio-ingress-lockdown-https
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      istio: ingress

  ingress:
  - toPorts:
    - ports:
      - port: "445"
        protocol: TCP
```
Generate the equivalent native network policy:

NetworkPolicy:
```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-ingress-lockdown-https
  namespace: default
spec:
  podSelector:
    matchLabels:
      istio: ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 445

```

#### Example 8 Redundancy

In this example we have three different policies and each of them enforces the same rule but in different ports.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-rule1
  namespace: default
spec:
  podSelector:
    matchLabels:
      istio: ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 449

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: istio-rule2
  namespace: default
spec:
  podSelector:
    matchLabels:
      istio: ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 448

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: iistio-rule3
  namespace: default
spec:
  podSelector:
    matchLabels:
      istio: ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 445

```

The model should detect that many several rules refer to the same endpoint. Output is a single policy that merges them.
