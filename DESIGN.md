## How does rexec work?

The setup consists of two parts, first we have a `ValidatingWebhookConfiguration` where, we deny requests targeting pod exec unless the user is allowed to bypass or the request is coming through the rexec endpont.

The second part is the rexec `APIService` where we receive exec request with the custom plugin. Here we modify the request back to a normal exec and audit it while proxying back to the kube apiserver. This proxyiing is happening through impersonation, as the user credentials are removed by the kube apiserver before being proxied to here.

![Diagram](diagram.png?raw=true "Diagram")