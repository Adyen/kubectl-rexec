# Getting started

For a proper installation you should use tagged images and your own implementation of kubernetes manifests, for a quick start however feel free to follow the instruction below.

## Installing proxy

The following command is going to install the proxy component, while adding a webhook that disables normal kubectl exec.

```
kustomize build manifests/ | kubectl -n kube-system apply -f -
```

## Installing the plugin

Ensure that you go bin directory is in the path.

```
go install github.com/adyen/kubectl-rexec@latest
```