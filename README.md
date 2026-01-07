# kubectl-rexec
![LOGO](LOGO.png)

Kubectl exec does not provide any kind of audit what is actually done inside the container. Rexec plugin is here to help with that.

## Contributing
We strongly encourage you to contribute to our repository. Find out more in our [contribution guidelines](https://github.com/Adyen/.github/blob/master/CONTRIBUTING.md)

## Requirements
The proxy now supports both websocket and SPDY exec streams. It works on clusters using the `TranslateStreamCloseWebsocketRequests` feature gate (websocket path) as well as older SPDY-based exec flows (e.g. EKS clusters without the websocket upgrade). Kubernetes versions below 1.29 remain unsupported.

## Installation
See the [Getting started](https://github.com/Adyen/kubectl-rexec/blob/master/STARTED.md) guide.

## Usage
See the [Getting started](https://github.com/Adyen/kubectl-rexec/blob/master/STARTED.md) guide.

## Testing
Tests are currently implemented for the rexec/server

Run the tests like:
`go test ./rexec/server`

## Documentation
See the [Design](https://github.com/Adyen/kubectl-rexec/blob/master/DESIGN.md).

## Support
If you have a feature request, or spotted a bug or a technical problem, create a GitHub issue.

## License    
MIT license. For more information, see the LICENSE file.