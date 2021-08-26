# K8's PCI Compliance Workshop

By default, Kubernetes is severly insecure - all pods can freely talk amongst themselves.
To prevent this, we will enforce a set of policies to adhere to those PCI standards:

## PCI Guide:
https://www.pcisecuritystandards.org/pdfs/pci_ssc_quick_guide.pdf

## Tigera PCI Whitepaper:
https://info.tigera.io/rs/805-GFH-732/images/tigera-assets-whitepaper-pci.pdf?mkt_tok=ODA1LUdGSC03MzIAAAF-jOpvGPypqiupw7CjVDlhYAmYiqn5N0qCNzU-y2zGzkLuEMH1JDZM-BPoG9iQ1IgGHkDGxYFQdCVG3ICdqstmIPwqTSKIjwG3ZyjJmkHE5w

## Configure log aggregation and flush intervals.

```
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
```

## Deploy our PCI Compliance Reports.

```
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: daily-cis-results
  labels:
    deployment: production
spec:
  reportType: cis-benchmark
  schedule: 0 0 * * *
  cis:
    highThreshold: 100
    medThreshold: 50
    includeUnscoredTests: true
    numFailedTests: 5
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/daily-cis-results.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: cluster-inventory
spec:
  reportType: inventory
  schedule: '*/30 * * * *'

---
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: cluster-network-access
spec:
  reportType: network-access
  schedule: '*/30 * * * *'

# uncomment policy-audit report if you configured audit logs for EKS cluster https://docs.tigera.io/compliance/compliance-reports/compliance-managed-cloud#enable-audit-logs-in-eks
# ---
# apiVersion: projectcalico.org/v3
# kind: GlobalReport
# metadata:
#   name: cluster-policy-audit
# spec:
#   reportType: policy-audit
#   schedule: '*/30 * * * *'
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/cluster-reports.yaml
```

## Deploy Global Alerts

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: policy.globalnetworkset
spec:
  description: "Alerts on any changes to global network sets"
  summary: "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}"
  severity: 100
  period: 5m
  lookback: 5m
  dataSet: audit
  # alert is triggered if CRUD operation executed against any globalnetworkset
  query: (verb=create OR verb=update OR verb=delete OR verb=patch) AND "objectRef.resource"=globalnetworksets
  aggregateBy: [objectRef.resource, objectRef.name]
  metric: count
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: policy.globalnetworkset
spec:
  description: "Alerts on any changes to global network sets"
  summary: "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}"
  severity: 100
  period: 1m
  lookback: 1m
  dataSet: audit
  # alert is triggered if CRUD operation executed against any globalnetworkset
  query: (verb=create OR verb=update OR verb=delete OR verb=patch) AND "objectRef.resource"=globalnetworksets
  aggregateBy: [objectRef.resource, objectRef.name]
  metric: count
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/globalnetworkset.changed.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: dns.unsanctioned.access
spec:
  description: "Pod attempted to access restricted.com domain"
  summary: "[dns] pod ${client_namespace}/${client_name_aggr} attempted to access '${qname}'"
  severity: 100
  dataSet: dns
  period: 5m
  lookback: 5m
  query: '(qname = "www.restricted.com" OR qname = "restricted.com")'
  aggregateBy: [client_namespace, client_name_aggr, qname]
  metric: count
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: dns.unsanctioned.access
spec:
  description: "Pod attempted to access google.com domain"
  summary: "[dns] pod ${client_namespace}/${client_name_aggr} attempted to access '${qname}'"
  severity: 100
  dataSet: dns
  period: 1m
  lookback: 1m
  query: '(qname = "www.google.com" OR qname = "google.com")'
  aggregateBy: [client_namespace, client_name_aggr, qname]
  metric: count
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.dns.access.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: network.lateral.access
spec:
  description: "Alerts when pods with a specific label (security=strict) accessed by other workloads from other namespaces"
  summary: "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} has accessed ${dest_namespace}/${dest_name_aggr} with label security=strict"
  severity: 100
  period: 5m
  lookback: 5m
  dataSet: flows
  query: '"dest_labels.labels"="security=strict" AND "dest_namespace"="secured_pod_namespace" AND "source_namespace"!="secured_pod_namespace" AND proto=tcp AND (("action"="allow" AND ("reporter"="dst" OR "reporter"="src")) OR ("action"="deny" AND "reporter"="src"))'
  aggregateBy: [source_namespace, source_name_aggr, dest_namespace, dest_name_aggr]
  field: num_flows
  metric: sum
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: network.lateral.access
spec:
  description: "Alerts when pods with a specific label (security=strict) accessed by other workloads from other namespaces"
  summary: "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} has accessed ${dest_namespace}/${dest_name_aggr} with label security=strict"
  severity: 100
  period: 1m
  lookback: 1m
  dataSet: flows
  query: '("dest_labels.labels"="security=strict" AND "dest_namespace"="dev") AND "source_namespace"!="dev" AND "proto"="tcp" AND (("action"="allow" AND ("reporter"="dst" OR "reporter"="src")) OR ("action"="deny" AND "reporter"="src"))'
  aggregateBy: [source_namespace, source_name_aggr, dest_namespace, dest_name_aggr]
  field: num_flows
  metric: sum
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.lateral.access.yaml
```

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

## Introduce a test application

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

## Create a Security Whitelist before the Security Blocklist

Whitelist - order:200
```
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security-whitelist
spec:
  order: 200
```
Blocklist - order:300
```
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security-blocklist
spec:
  order: 300
```

## Whitelist traffic for Kube-DNS
To avoid any interruptions caused by the blocklists, we should explictly allow traffic for kube-dns:
https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security-whitelist.allow-kube-dns
spec:
  tier: security-whitelist
  order: 150
  selector: all()
  namespaceSelector: ''
  serviceAccountSelector: ''
  egress:
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        selector: k8s-app == "kube-dns"
        ports:
          - '53'
    - action: Pass
      source: {}
      destination: {}
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Egress
```

# Create a PCI Whitelist policy
The Payment Card Industry (PCI) Data Security Standard (DSS) is an information security compliance standard which requires merchants and other businesses to handle credit card information in a secure manner that helps reduce the likelihood that cardholders would have sensitive financial account information stolen. In our case, we will try to securely allow workloads that handle payment details to talk to workloads that remain compliant.

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security-whitelist.pci-whitelist
spec:
  tier: security-whitelist
  order: 155
  selector: ''
  namespaceSelector: ''
  serviceAccountSelector: PCI == "true"
  ingress:
    - action: Deny
      source:
        serviceAccounts:
          names: []
          selector: PCI != "true"
      destination:
        serviceAccounts:
          names: []
          selector: PCI == "true"
  egress:
    - action: Pass
      source: {}
      destination:
        selector: k8s-app == "kube-dns"||has(dns.operator.openshift.io/daemonset-dns)
    - action: Pass
      source: {}
      destination:
        selector: type == "public"
    - action: Deny
      source:
        serviceAccounts:
          names: []
          selector: PCI == "true"
      destination:
        serviceAccounts:
          names: []
          selector: PCI != "true"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
```


## Block Traffic from an Embargoed Region

Users commonly ask how to block traffic some unwanted regions if this is part of an internal company standard or part of a broader security best practice:
https://community.cisco.com/t5/network-security/block-all-russia-public-ip-addresses/td-p/2094303

Here is a cool 3rd-party tool where you can put in a country and it can output the IP/CIDR range for network policies: 
https://www.countryipblocks.net/country_selection.php

Using this IP list generator, you could generate an arbitrary set of IP subnetworks/CIDRs - which we can assign to a Calico-specific resource called a ```GlobalNetworkSet```. This allows admins to match potentially unwanted traffic to our Calico policies.

## Block Traffic from endpoints associated with malware

With respect to PCI Controls 5.1, 5.2, 5.3, 5.4, 10.6 and 11.4, we need to update antivirus software and review relevent logs for anomalous and suspicious activity. If we were to use this same ```IPSet``` idea, we can create another Calico resource ```GlobalThreatFeed``` to automatically identify and block inbound or outbound connections to IP addresses associated with bad actors (ie: Malware C2 Servers).

```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: feodo-tracker
spec:
  content: IPSet
  pull:
    http:
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  globalNetworkSet:
    labels:
      threat-feed: feodo
```

## Designing a policy to automatically block traffic to feodo-tracker feeds

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: security.block-feodo
spec:
  tier: security
  order: 210
  selector: projectcalico.org/namespace != "acme"
  namespaceSelector: ''
  serviceAccountSelector: ''
  egress:
    - action: Deny
      source: {}
      destination:
        selector: threatfeed == "feodo"
    - action: Log
      source: {}
      destination:
        selector: threatfeed == "feodo"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Egress
```    

## Automatically Identify Potential Anonymization Attacks

Tor and VPN infrastructure are used in enabling anonymous communication, where an attacker can leverage anonymity to scan, attack or compromise the target. It’s hard for network security teams to track malicious actors using such anonymization tools. Hence Tor and VPN feeds come into play where the feeds track all the Tor bulk exit nodes as well as most of the anonymising VPN infrastructure on the internet.

```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: tor-bulk-exit-list
spec:
  pull:
    http:
      url: https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1
  globalNetworkSet:
    labels:
      feed: tor
```

Tor is a popular anonymization network on the internet. It is also popular among the malicious actors, hacktivist groups, criminal enterprises as the infrastructure hides the real identity of an attacker carrying out malicious activities. To track down such attackers, Tor historically was subject to investigation by various state level intelligence agencies from US and UK for criminal activities such as Silk Road marketplace, Mirai Botnet C&C. Though it’s not possible to completely de-anonymize the attacker. Hence Tor bulk exit feed came into existence to track all the Tor exit IPs over the internet to know attackers using the Tor infrastructure. Over the years, many Tor flaws became public and attackers evolved to leverage Tor network with additional VPN layers. There are many individual VPN providers which have the anonymizing infrastructure. Attackers can use these new breed of VPN providers with existing options like Tor to make sure of anonymity. To help security teams, the EJR vpn feed detects all the major VPN providers on the internet.

```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: ejr-vpn
spec:
  pull:
    http:
      url: https://raw.githubusercontent.com/ejrv/VPNs/master/vpn-ipv4.txt
  globalNetworkSet:
    labels:
      feed: ejr-vpn
```

# Automically block those attempted Anonymization Attacks

Tor Bulk Exit feed The Tor Bulk Exit feed lists available Tor exit nodes on the internet which are used by Tor network. The list continuously updated and maintained by the Tor project. An attacker using Tor network, is likely to use one of the bulk exit nodes to connect to your infrastructure. The network security teams can detect such activity with Tor bulk exit feed and investigate as required.

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: security-blocklist.anonymization-feed
spec:
  tier: security-blocklist
  order: 210
  selector: ''
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Deny
      source:
        selector: feed == "ejr-vpn"||feed == "tor"
      destination: {}
  egress:
    - action: Deny
      source: {}
      destination:
        selector: feed == "ejr-vpn"||feed == "tor"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
``` 

EJR VPN feed In recent times it became a trend to use multiple anonymization networks to hide real attacker identity. The EJR VPN feed targets major VPN providers and their infrastructure used in anonymization activity over the internet. The feed is updated bi-monthly, which helps network security teams to stay on top of threats from such anonymizing infrastructure and detect them early in the enumeration phase.

# Protect against Monero attacks

The Christmas Day attack against Monero full nodes was largely mitigated by the ban-list of bad i.p.'s at https://gui.xmr.pm/files/block_tor.txt . Knowledgeable full node owners saw their nodes down, instituted the ban-list and were back up and running immediately.

A ban-list is, IMO, the most effective deterrent against bad actors. You cannot transmit anything on the internet without an i.p. address. Doesn't matter if it's real or fake, you have to have an address. It is the one flaw of the internet that works overwhelmingly in favor of an address ban-list.

```
apiVersion: projectcalico.org/v3
kind: GlobalThreatFeed
metadata:
  name: monero-feed
spec:
  pull:
    http:
      url: https://gui.xmr.pm/files/block_tor.txt
  globalNetworkSet:
    labels:
      feed: monero-feed
```

So why not a Monero ban-list on Git-Hub? There could be pull requests as future bad addresses come up. The addresses could be verified as to what they are doing and then added to the list.

Some may say, "well it's centralization of Monero". No it's not. A ban-list is a suggested list of bad addresses to be included, at your discretion, when starting up Monerod. We all download the Monero code from Git-Hub or GetMonero.org. No one says that's centralization of the coin, do we? Of course not.

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: default.monero-feed
spec:
  tier: default
  order: 210
  selector: ''
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Deny
      source:
        selector: feed == "monero"
      destination: {}
  egress:
    - action: Deny
      source: {}
      destination:
        selector: feed == "monero"
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
```

A Git-Hub ban-list is a simple fix that puts bad actors in a tizzy because how do you get around the list? You can't for very long when you have people looking and filing pull requests on your i.p. address immediately on Git Hub.
