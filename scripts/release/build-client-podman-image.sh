#!/bin/bash

SCRIPT_DIR=$(cd `dirname $0`; pwd)
PROJECT_DIR="$SCRIPT_DIR/../.."
DOCKER_DIR=$PROJECT_DIR/docker
DOCKER_RELEASE_DIR=$DOCKER_DIR/target/release

if [ $# -lt 1 ]; then
        echo "Usage: $0 <TAG>"
        exit 1
fi
TAG=$1

REPOSITORY=ackingliu/http2-client
IMAGE_ADDRESS=$REPOSITORY:$TAG
DOCKER_FILE=http2-client.dockerfile

# prepare binaries
rm -rf $DOCKER_RELEASE_DIR > /dev/null 2>&1
mkdir -p $DOCKER_RELEASE_DIR
cp $PROJECT_DIR/target/release/http-proxy-client $DOCKER_RELEASE_DIR/

# change dir
cd $DOCKER_DIR

# build docker image
echo "1. Start build $IMAGE_ADDRESS"
sudo podman build -t $IMAGE_ADDRESS -f $DOCKER_FILE .

echo "2. Start push $IMAGE_ADDRESS. Note: Please to login your podman account "
sudo podman push $IMAGE_ADDRESS
