IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= devel
IMAGE_EXT_VERSION ?= 1.1.0-beta.13-dev
CONTAINER_TOOL_ARGS ?=
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
CONTAINER_BUILD_ARGS ?=
MARKDOWN_FORMAT_ARGS ?= --options-line-width=100
CONTAINER_TOOL ?= docker
BUILDKIT_PROGRESS ?= plain
TESTS ?=
BOOK_VERSION ?= master

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: buildx/kanidmd
buildx/kanidmd: ## Build multiarch kanidm server images and push to docker hub
buildx/kanidmd:
	@echo $(IMAGE_EXT_VERSION)
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f server/Dockerfile \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		-t $(IMAGE_BASE)/server:$(IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/kanidm_tools
buildx/kanidm_tools: ## Build multiarch kanidm tool images and push to docker hub
buildx/kanidm_tools:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f tools/Dockerfile \
		-t $(IMAGE_BASE)/tools:$(IMAGE_VERSION) \
		-t $(IMAGE_BASE)/tools:$(IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/radiusd
buildx/radiusd: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f rlm_python/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		-t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) \
		-t $(IMAGE_BASE)/radius:$(IMAGE_EXT_VERSION) .

.PHONY: buildx
buildx: buildx/kanidmd buildx/kanidm_tools buildx/radiusd

.PHONY: build/kanidmd
build/kanidmd:	## Build the kanidmd docker image locally
build/kanidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--platform $(IMAGE_ARCH) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/radiusd
build/radiusd:	## Build the radiusd docker image locally
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		--platform $(IMAGE_ARCH) \
		-f rlm_python/Dockerfile \
		-t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) .

.PHONY: build
build: build/kanidmd build/radiusd

.PHONY: test/kanidmd
test/kanidmd: ## Run cargo test in docker
test/kanidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		--target builder \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(IMAGE_BASE)/server:$(IMAGE_VERSION)-builder cargo test

.PHONY: test/radiusd
test/radiusd: ## Run a test radius server
test/radiusd: build/radiusd
	cd rlm_python && \
	./run_radius_container.sh

.PHONY: test
test:
	cargo test

.PHONY: precommit
precommit: ## all the usual test things
precommit: test codespell test/pykanidm doc/format

.PHONY: vendor
vendor:
	cargo vendor > cargo_vendor_config

.PHONY: vendor-prep
vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

.PHONY: install-tools
install-tools: ## install kanidm_tools in your local environment
install-tools:
	cargo install --path tools/cli --force

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	-L 'crate,unexpect,Pres,pres,ACI,aci,te,ue,unx,aNULL' \
	--skip='./target,./pykanidm/.venv,./pykanidm/.mypy_cache,./.mypy_cache,./pykanidm/poetry.lock' \
	--skip='./book/book/*' \
	--skip='./docs/*,./.git' \
	--skip='./rlm_python/mods-available/eap' \
	--skip='./server/web_ui/static/external,./server/web_ui/pkg/external' \
	--skip='./server/lib/src/constants/system_config.rs,./pykanidm/site,./server/lib/src/constants/*.json'

.PHONY: test/pykanidm/pytest
test/pykanidm/pytest: ## python library testing
	cd pykanidm && \
	poetry install && \
	poetry run pytest -vv

.PHONY: test/pykanidm/lint
test/pykanidm/lint: ## python library linting
	cd pykanidm && \
	poetry install && \
	poetry run ruff tests kanidm

.PHONY: test/pykanidm/mypy
test/pykanidm/mypy: ## python library type checking
	cd pykanidm && \
	poetry install && \
	echo "Running mypy" && \
	poetry run mypy --strict tests kanidm

.PHONY: test/pykanidm
test/pykanidm: ## run the kanidm python module test suite (mypy/lint/pytest)
test/pykanidm: test/pykanidm/pytest test/pykanidm/mypy test/pykanidm/lint

########################################################################

.PHONY: doc
doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

.PHONY: doc/format
doc/format: ## Format docs and the Kanidm book
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' \
		-name \*.md \
		-exec deno fmt --check $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Kanidm book
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' \
		-name \*.md \
		-exec deno fmt  $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: book
book: ## Build the Kanidm book
book:
	cargo doc --no-deps
	mdbook build book
	rm -rf ./docs/
	mv ./book/book/ ./docs/
	mkdir -p ./docs/rustdoc/${BOOK_VERSION}
	mv ./target/doc/* ./docs/rustdoc/${BOOK_VERSION}/

.PHONY: book_versioned
book_versioned:
	echo "Book version: ${BOOK_VERSION}"
	rm -rf ./target/doc
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mkdir -p ./docs
	mv ./book/book/ ./docs/${BOOK_VERSION}/
	mkdir -p ./docs/${BOOK_VERSION}/rustdoc/
	mv ./target/doc/* ./docs/${BOOK_VERSION}/rustdoc/
	git switch master

.PHONY: clean_book
clean_book:
	rm -rf ./docs

.PHONY: docs/pykanidm/build
docs/pykanidm/build: ## Build the mkdocs
docs/pykanidm/build:
	cd pykanidm && \
	poetry install && \
	poetry run mkdocs build

.PHONY: docs/pykanidm/serve
docs/pykanidm/serve: ## Run the local mkdocs server
docs/pykanidm/serve:
	cd pykanidm && \
	poetry install && \
	poetry run mkdocs serve

########################################################################

.PHONY: release/prep
prep:
	cargo outdated -R
	cargo audit

.PHONY: release/kanidm
release/kanidm: ## Build the Kanidm CLI - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p kanidm_tools --bin kanidm --release

.PHONY: release/kanidmd
release/kanidmd: ## Build the Kanidm daemon - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build -p daemon --bin kanidmd --release

.PHONY: release/kanidm-ssh
release/kanidm-ssh: ## Build the Kanidm SSH tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
	cargo build --release \
		--bin kanidm_ssh_authorizedkeys \
		--bin kanidm_ssh_authorizedkeys_direct

.PHONY: release/kanidm-unixd
release/kanidm-unixd: ## Build the Kanidm UNIX tools - ensure you include the environment variable KANIDM_BUILD_PROFILE
release/kanidm-unixd:
	cargo build -p pam_kanidm --release
	cargo build -p nss_kanidm --release
	cargo build --features unix -p kanidm_unix_int --release \
		--bin kanidm_unixd \
		--bin kanidm_unixd_tasks \
		--bin kanidm-unix

# cert things

.PHONY: cert/clean
cert/clean: ## clean out the insecure cert bits
cert/clean:
	rm -f /tmp/kanidm/*.pem
	rm -f /tmp/kanidm/*.cnf
	rm -f /tmp/kanidm/*.csr
	rm -f /tmp/kanidm/ca.txt*
	rm -f /tmp/kanidm/ca.{cnf,srl,srl.old}

.PHONY: webui
webui: ## Build the WASM web frontend
	cd server/web_ui && ./build_wasm_release.sh

.PHONY: webui/test
webui/test: ## Run wasm-pack test
	cd server/web_ui && wasm-pack test --headless --chrome

.PHONY: rust/coverage
coverage/test: ## Run coverage tests
coverage/test:
	LLVM_PROFILE_FILE="$(PWD)/target/profile/coverage-%p-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test $(TESTS)

.PHONY: coverage/grcov
coverage/grcov: ## Run grcov
coverage/grcov:
	rm -rf ./target/coverage/html/*
	grcov . --binary-path ./target/debug/deps/ \
		-s . \
		-t html \
		--branch \
		--ignore-not-existing \
		--ignore '../*' \
		--ignore "/*" \
		-o target/coverage/html/

.PHONY: coverage
coverage: ## Run all the coverage tests
coverage: coverage/test coverage/grcov
	echo "Coverage report is in ./target/coverage/html/index.html"