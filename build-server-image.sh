rm -rf ./target
IMAGE_NAME="http2-server"
echo "Start build $IMAGE_NAME image"
docker build -f server.dockerfile . -t $IMAGE_NAME
echo "Build $IMAGE_NAME successful"

TAG_NAME="ackingliu/$IMAGE_NAME:v2"

echo "Tag with $TAG_NAME"
docker tag $IMAGE_NAME $TAG_NAME

echo "Start push $TAG_NAME. Note: Please to login your docker account"
docker push $TAG_NAME