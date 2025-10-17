# Copy a pre-cross-compiled binary into an alpine container.
# Use alpine because we can get setcap in the container, so macos can build the images.
FROM alpine AS build
RUN apk add libcap-setcap
ARG TARGETOS
ARG TARGETARCH
COPY $TARGETOS/$TARGETARCH /dns
RUN setcap 'cap_net_bind_service+ep' /dns

# Then copy the setcap'd binary into our final dockerfile
FROM gcr.io/distroless/static:nonroot
WORKDIR /
USER 65532:65532
ENTRYPOINT ["/dns"]
COPY --from=build /dns /dns
