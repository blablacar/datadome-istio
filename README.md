# This is our integration for datadome on the istio ingress gateways

Istio uses envoy as a reverse proxy for both it's service-to-service mesh and for ingress into a kubernetes cluster.

Integration with the datadome protection API is done via an envoy lua filter.

This repo is used to integrate the lua envoy filter provided by datadome with our istio setup, allowing us to version the lua file independantly of the EnvoyFilter CRD that embeds it, to facilitate merging upstream changes.