#!/bin/bash

SCRIPT_DIR=$(cd `dirname $0`; pwd)
PROJECT_DIR="$SCRIPT_DIR/../.."
PODMAN_DIR=$PROJECT_DIR/docker
PODMAN_RELEASE_DIR=$PODMAN_DIR/target/release

if [ $# -lt 1 ]; then
        echo "Usage: $0 <TAG>"
        exit 1
fi
TAG=$1

REPOSITORY=ackingliu/http2-server
IMAGE_ADDRESS=$REPOSITORY:$TAG
DOCKER_FILE=http2-server.dockerfile

# prepare binaries
rm -rf $PODMAN_RELEASE_DIR > /dev/null 2>&1
mkdir -p $PODMAN_RELEASE_DIR
cp $PROJECT_DIR/target/release/http-proxy-server $PODMAN_RELEASE_DIR/

# change dir
cd $PODMAN_DIR

# build podman image
echo "1. Start build $IMAGE_ADDRESS"
sudo podman build -t $IMAGE_ADDRESS -f $DOCKER_FILE .

echo "2. Start push $IMAGE_ADDRESS. Note: Please to login your podman account "
sudo podman push $IMAGE_ADDRESS
