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

### Copy Files

```
kubectl rexec cp /tmp/myfile.txt my-pod:/tmp/myfile.txt

kubectl rexec cp my-pod:/var/log/app.log /tmp/app.log

kubectl rexec cp ./configs/ my-pod:/etc/configs/

kubectl rexec cp /tmp/file.txt my-pod:/tmp/file.txt -c my-container
```

## View Audit Logs

Tail the logs to see all audited operations:

```
kubectl -n kube-system logs -l app=rexec -f
```

Example audit entries:

```
{"level":"info","facility":"audit","user":"alice","session":"oneoff","command":"tar xf - -C /tmp","time":"2024-12-16T10:30:01Z"}
{"level":"info","facility":"audit","user":"bob","session":"a1b2c3d4","command":"ls -la","time":"2024-12-16T10:31:15Z"}
```