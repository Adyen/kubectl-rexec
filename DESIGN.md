## How does rexec work?

The setup consists of two parts. First, we have a `ValidatingWebhookConfiguration` where we deny requests targeting pod exec unless the user is allowed to bypass or the request is coming through the rexec endpoint.

The second part is the rexec `APIService` where we receive exec requests from the custom plugin. Here we modify the request back to a normal exec and audit it while proxying it back to the kube apiserver. This proxying happens through impersonation, as the user credentials are removed by the kube apiserver before the request is proxied here.

![Diagram](diagram.png?raw=true "Diagram")