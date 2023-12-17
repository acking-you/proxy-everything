# 检查是否设置了TAG环境变量
if [ -z "$TAG" ]; then
    # 如果TAG环境变量未设置，则使用默认值v2
    TAG="v2"
fi
rm -rf ./target
IMAGE_NAME="http2-server"
echo "Start build $IMAGE_NAME image"
docker build -f server.dockerfile . -t $IMAGE_NAME
echo "Build $IMAGE_NAME successful"

TAG_NAME="ackingliu/$IMAGE_NAME:$TAG"

echo "Tag with $TAG_NAME"
docker tag $IMAGE_NAME $TAG_NAME

echo "Start push $TAG_NAME. Note: Please to login your docker account"
docker push $TAG_NAME