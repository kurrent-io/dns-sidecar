#!/bin/sh

set -e

VERSION="$(cat VERSION)"
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

if [ "$#" -eq 0 ] ; then
    echo "usage: ./build.sh (build|image|publish-staging|publish-prod)..."
    exit 0
fi

# parse args
for arg in "$@" ; do
    case "$arg" in
        build) want_build=y;;
        image) want_cross_compile=y; want_image=y;;
        publish-staging) want_cross_compile=y; want_publish_staging=y;;
        publish-prod) want_cross_compile=y; want_publish_prod=y;;
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
fi

if [ -n "$want_image" ] ; then
    show docker build -t $IMAGE -f Dockerfile build/docker
fi

publish () {
    repo="$1"
    # replace download-name/kurrent-latest with upload-name/$repo
    image="docker.cloudsmith.io/eventstore/$repo/${IMAGE#docker.kurrent.io/kurrent-latest/}"
    show docker buildx build \
        --push \
        --provenance=false \
        --sbom=false \
        --platform=linux/arm64/v8,linux/amd64 \
        -t=$image \
        -f Dockerfile \
        build/docker
}

if [ -n "$want_publish_staging" ] ; then
    publish "kurrent-staging"
fi

if [ -n "$want_publish_prod" ] ; then
    publish "kurrent-latest"
fi
