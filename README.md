# DNS sidecar image

This image serves as a small sidecar container in KurrentDB deployments, as deployed by the
[kurrentdb-operator](https://docs.kurrent.io/server/kubernetes-operator).

## Building

Just run `build.sh build` or `build.sh image`.

## Testing

Just run `go test ./dns`.

## Publishing

Just run `build.sh publish-staging` or `build.sh publish-prod`.
