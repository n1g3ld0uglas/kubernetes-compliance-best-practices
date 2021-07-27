# kubernetes-compliance-best-practices

By default, Kubernetes is severly insecure - all pods can freely talk amongst themselves.
To prevent this, we will enforce a set of policies depending on regularly standards we need to adhere to.

# Create a Default-Deny

The first thing we would do is enforce a default-deny.
However, this would deny all existing traffic, so we need to explicitly allow wanted traffic before we would enforce a default-deny policy.
As a result, we will use the Calico-specific policy object - 'StagedGlobalNetworkPolicy'

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: default.catch-all-default-deny
spec:
  tier: default
  order: 1000
  selector: ''
  namespaceSelector: ''
  serviceAccountSelector: ''
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
```

I've specified order '1000' to ensure this policy is evaluated after all other network policies within the 'default' tier of Calico Enterprise.
We can observe the traffic that would have been denied via policy - however, this will have no effect on existing traffic until the policy is applied.

# Introduce a test application

We need to introduce a test application. Once introduced, we would preferably create a zone-based architecture for those workloads - only explicly allowing traffic that we trust within each zone: 
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml
```

Confirm all workloads have the zone-based firewall-zone labels assigned to the correct pods:

```
kubectl get pods -n storefront --show-labels
```

Demilitarized (DMZ) Zone:
```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/kubernetes-compliance-best-practices/main/ZoneBasedArchitecture/dmz.yaml
```

Trusted Zone:
```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/kubernetes-compliance-best-practices/main/ZoneBasedArchitecture/trusted.yaml
```

Restricted Zone:
```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/kubernetes-compliance-best-practices/main/ZoneBasedArchitecture/restricted.yaml
```

# Introduce a test application
