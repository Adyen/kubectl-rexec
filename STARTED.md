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

## Verify Installation
```
kubectl rexec exec --help
kubectl rexec cp --help
```

Tail the logs of the proxy to see audit events, and ideally set up a logshipping setup that suits you to store them.

```
kubectl -n kube-system logs -l app=rexec -f
```

## Use the plugin

The rexec plugin has the same params as the upstream exec and cp commands.

### Execute Commands

```
kubectl rexec exec -ti my-pod -- bash

kubectl rexec exec my-pod -- ls -la /tmp

kubectl rexec exec my-pod -c my-container -- env
```

### Copy Files (Download Only)

For security reasons, only copying FROM pods is supported.

Note: The `cp` command requires the `tar` binary to be installed and available in the PATH of the target container.

```
kubectl rexec cp my-pod:/var/log/app.log /tmp/app.log

kubectl rexec cp my-pod:/tmp/data /tmp/data

kubectl rexec cp my-pod:/var/log/app.log ./app.log -c my-container

kubectl rexec cp my-namespace/my-pod:/etc/config ./config
```

## View Audit Logs

Tail the logs to see all audited operations:

```
kubectl -n kube-system logs -l app=rexec -f
```

Example audit entries:

```
{"level":"info","facility":"audit","user":"alice","session":"f1e2d3c4-b5a6-7f8e-9d0c-1a2b3c4d5e6f","command":"tar cf - -C /var/log -- app.log","time":"2024-12-16T10:30:01Z"}
{"level":"info","facility":"audit","user":"bob","session":"94f1add8-7f29-4b18-b259-99f68605149e","command":"ls -la","time":"2024-12-16T10:31:15Z"}
```