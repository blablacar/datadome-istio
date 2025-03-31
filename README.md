# Introduction

This repo contain an Helm Chart used to integrate the lua envoy filter provided by datadome with our istio setup.

It allow us to version the lua file independantly of the EnvoyFilter CRD that embeds it in order to facilitate merging upstream changes.

# Prerequisites

- Kubernetes 1.20+

- Istio

# Installing the Chart

To install the chart with the release name my-release:

`helm install my-release datadome-istio`

Tip: List all releases using `helm list`

# Uninstalling the Chart

To uninstall/delete the my-release deployment:

`helm delete my-release`

The command removes all the Kubernetes components associated with the chart and deletes the release.

# Configuration

The following table lists the configurable parameters of the datadome-istio chart and their default values.

Parameter|Description|Default
-|-|-
destinationRule.enabled | Add a `destinationRule` resource | true
serviceEntry.enabled | Add a `serviceEntry` resource | true
istio.portNumber | Istio port number| 8080
istio.proxyVersion |Match specific proxy version [(EnvoyFilter.ProxyMatch)](https://istio.io/latest/docs/reference/config/networking/envoy-filter/#EnvoyFilter-ProxyMatch) |
istio.workloadSelector.labels | List of labels to select envoy proxys | `datadome: 'enabled'`
datadome.api_key|Datadome API key|TOP_SECRET_API_KEY
datadome.api_url|Datadome API url|api.datadome.co
datadome.api_timeout| Timeout to Datadome API in milliseconds| 200
datadome.api_connection_timeout| Connection timeout to Datadome API in milliseconds (golang time format) | "100ms"
datadome.uri_patterns_exclusions |List of all URI patterns (domain + path) NOT redirected to Datadome|
datadome.uri_patterns|List of all URI patterns (domain + path) redirected to Datadome|

# Filter

The filters are evaluated in the following order:

url_patterns → uri_patterns_exclusions → uri_patterns

Place your most specific rules first.

Each entry is using LUA pattern matching, documentation can be found [here](https://www.lua.org/pil/20.2.html).

```text
Note : % is the escaping character and negation inside the pattern is not available.
```

# Helm Release Example

```
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: my-release
  namespace: istio-system
spec:
  interval: 1m
  chart:
    spec:
      chart: datadome-istio
      reconcileStrategy: Revision
      sourceRef:
        kind: GitRepository
        name: datadome-istio
  upgrade:
    remediation:
      retries: 3
  rollback:
    cleanupOnFail: true
  valuesFrom:
    - kind: Secret
      name: datadome
      targetPath: datadome.api_key
      valuesKey: api_key
  values:
    istio:
      portNumber: 8080
      workloadSelector:
        labels:
          datadome: "enabled"
    datadome:
      api_url: api.datadome.co
      api_timeout: 200
      api_connection_timeout: "1s"
      uri_patterns_exclusion:
        - "%.avi$"
        - "%.flv$"
      uri_patterns:
        - "^api%.my-domain%.com/api/route1
```
