#!/bin/sh

set -e

VERSION="1.0.2"
IMAGE="docker.kurrent.io/kurrent-latest/dns:$VERSION"

show () {
    printf "\033[90m%s\033[m\n" "$*"
    (
        # export NAME=VALUE env vars at beginning of command
        while [ "$#" -gt 0 ] ; do
            test "${1#*=}" != "$1" && export "$1" && shift || break
        done
        # then execute the command
        "$@"
    )
}

cd "$(dirname "$0")"

want_build=
want_image=
want_cross_compile=
want_publish_prod=
redhat_only="n"

if [ "$#" -eq 0 ] ; then
    echo "usage: ./build.sh (build|image|publish-staging|publish-prod)... [--redhat-only]"
    exit 0
fi

# parse args
for arg in "$@" ; do
    case "$arg" in
        build) want_build=y;;
        image) want_cross_compile=y; want_image=y;;
        publish-staging) want_cross_compile=y; want_publish_staging=y;;
        publish-prod) want_cross_compile=y; want_publish_prod=y;;
        --redhat-only) redhat_only="y";;
        *) echo "unrecognized target: $arg"; exit 1;;
    esac
done

show go mod tidy

compile () {
    dst="$1"
    tmp="/tmp/build.sh-$$"
    mkdir -p $(dirname $dst)
    go build -o $tmp main.go
    test -e $dst && diff $tmp $dst >/dev/null && rm $tmp || mv $tmp $dst
}

if [ -n "$want_build" ] ; then
    show compile build/dns
fi

if [ -n "$want_cross_compile" ] ; then
    show GOOS=linux GOARCH=amd64 compile build/docker/linux/amd64
    show GOOS=linux GOARCH=arm64 compile build/docker/linux/arm64
    mkdir -p build/docker/licenses
    cp LICENSE.txt build/docker/licenses
fi

dynamic_labels () {
    echo --label release="$(git rev-parse --short=8 HEAD)" --label version=$VERSION
}

docker_build () {
    show docker build -f Dockerfile $(dynamic_labels) build/docker -t "$@"
}

if [ -n "$want_image" ] ; then
    test "$redhat_only" = "y" || docker_build $IMAGE
    docker_build $IMAGE-rhel8 --build-arg BASE="registry.access.redhat.com/ubi8/ubi-micro"
fi

publish () {
    repo="$1"
    # replace download-name/kurrent-latest with upload-name/$repo
    dst="docker.cloudsmith.io/eventstore/$repo/${IMAGE#docker.kurrent.io/kurrent-latest/}"

    # publish standard image
    if [ "$redhat_only" != "y" ] ; then
        show podman build \
            --platform linux/arm64/v8,linux/amd64 \
            --manifest $IMAGE \
            $(dynamic_labels) \
            -f Dockerfile \
            build/docker

        show podman manifest push $IMAGE $dst
    fi

    # publish redhat image, with --pull-always so we can rebuild vulnerabile rhel8 base images
    podman rm $IMAGE-rhel8 2>/dev/null || true
    show podman build \
        --platform linux/arm64/v8,linux/amd64 \
        --manifest $IMAGE-rhel8 \
        $(dynamic_labels) \
        -f Dockerfile \
        build/docker \
        --pull=always \
        --build-arg BASE="registry.access.redhat.com/ubi8/ubi-micro"

    show podman manifest push "$IMAGE-rhel8" "$dst-rhel8"
}

if [ -n "$want_publish_staging" ] ; then
    publish "kurrent-staging"
fi

if [ -n "$want_publish_prod" ] ; then
    publish "kurrent-latest"
fi
