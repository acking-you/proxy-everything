TAG ?= dev
CRATES ?= proxy-core proxy-client proxy-server proxy-tui proxy-ffi

build-client-release:
	bash ./scripts/build/build-client-release.sh

build-cli-release:
	bash ./scripts/build/build-cli-release.sh

build-server-release:
	bash ./scripts/build/build-server-release.sh

build-client-docker-image: build-client-release
	bash ./scripts/release/build-client-docker-image.sh ${TAG}

build-server-docker-image: build-server-release
	bash ./scripts/release/build-server-docker-image.sh ${TAG}

build-client-podman-image: build-client-release
	bash ./scripts/release/build-client-podman-image.sh ${TAG}

build-server-podman-image: build-server-release
	bash ./scripts/release/build-server-podman-image.sh ${TAG}

fmt:
	cargo fmt $(foreach c,$(CRATES),-p $(c))

clippy:
	cargo clippy $(foreach c,$(CRATES),-p $(c))

test:
	cargo test $(foreach c,$(CRATES),-p $(c))

.PHONY: build-client-release build-cli-release build-server-release \
	build-client-docker-image build-server-docker-image \
	build-client-podman-image build-server-podman-image \
	fmt clippy test
