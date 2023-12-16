rm -rf ./target
IMAGE_NAME="http2-client"
echo "Start build $IMAGE_NAME image"
docker build -f client.dockerfile . -t $IMAGE_NAME
echo "Build $IMAGE_NAME successful"

TAG_NAME="ackingliu/$IMAGE_NAME:v2"

echo "Tag with $TAG_NAME"
docker tag http2-client $TAG_NAME

echo "Start push $TAG_NAME. Note: Please to login your docker account"
docker push $TAG_NAME