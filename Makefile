IMAGE_BASE ?= kanidm
IMAGE_VERSION ?= devel
IMAGE_EXT_VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "daemon")  | .version')
CONTAINER_TOOL_ARGS ?=
IMAGE_ARCH ?= "linux/amd64,linux/arm64"
CONTAINER_BUILD_ARGS ?=
MARKDOWN_FORMAT_ARGS ?= --options-line-width=100
CONTAINER_TOOL ?= docker
BUILDKIT_PROGRESS ?= plain
KANIDM_FEATURES ?= ""
TESTS ?=
BOOK_VERSION ?= master
GIT_COMMIT := $(shell git rev-parse HEAD)

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.PHONY: config
config: ## Show makefile config things
config:
	@echo "IMAGE_BASE: $(IMAGE_BASE)"
	@echo "IMAGE_VERSION: $(IMAGE_VERSION)"
	@echo "IMAGE_EXT_VERSION: $(IMAGE_EXT_VERSION)"
	@echo "CONTAINER_TOOL_ARGS: $(CONTAINER_TOOL_ARGS)"
	@echo "IMAGE_ARCH: $(IMAGE_ARCH)"
	@echo "CONTAINER_BUILD_ARGS: $(CONTAINER_BUILD_ARGS)"
	@echo "MARKDOWN_FORMAT_ARGS: $(MARKDOWN_FORMAT_ARGS)"
	@echo "CONTAINER_TOOL: $(CONTAINER_TOOL)"
	@echo "BUILDKIT_PROGRESS: $(BUILDKIT_PROGRESS)"
	@echo "TESTS: $(TESTS)"
	@echo "BOOK_VERSION: $(BOOK_VERSION)"
	@echo "GIT_COMMIT: $(GIT_COMMIT)"

.PHONY: run
run: ## Run the test/dev server
run:
	cd server/daemon && ./run_insecure_dev_server.sh

.PHONY: run_htmx
run_htmx: ## Run in HTMX mode
run_htmx:
	cd server/daemon && KANI_CARGO_OPTS="--features kanidmd_core/ui_htmx" ./run_insecure_dev_server.sh

.PHONY: buildx/kanidmd
buildx/kanidmd: ## Build multiarch kanidm server images and push to docker hub
buildx/kanidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f server/Dockerfile \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		-t $(IMAGE_BASE)/server:$(IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--compress \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
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
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/radiusd
buildx/radiusd: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull --push --platform $(IMAGE_ARCH) \
		-f rlm_python/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
		-t $(IMAGE_BASE)/radius:$(IMAGE_VERSION) \
		-t $(IMAGE_BASE)/radius:$(IMAGE_EXT_VERSION) .

.PHONY: buildx
buildx: buildx/kanidmd buildx/kanidm_tools buildx/radiusd

.PHONY: build/kanidmd
build/kanidmd:	## Build the kanidmd docker image locally
build/kanidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		-t $(IMAGE_BASE)/server:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/orca
build/orca:	## Build the orca docker image locally
build/orca:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f tools/orca/Dockerfile \
		-t $(IMAGE_BASE)/orca:$(IMAGE_VERSION) \
		--build-arg "KANIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KANIDM_FEATURES=$(KANIDM_FEATURES)" \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/radiusd
build/radiusd:	## Build the radiusd docker image locally
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f rlm_python/Dockerfile \
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
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
		--label "com.kanidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kanidm.version=$(IMAGE_EXT_VERSION)" \
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
vendor: ## Vendor required crates
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
	-D .codespell_dictionary \
	--ignore-words .codespell_ignore \
	--skip='./target,./pykanidm/.venv,./pykanidm/.mypy_cache,./.mypy_cache,./pykanidm/uv.lock' \
	--skip='./book/*.js' \
	--skip='./book/book/*' \
	--skip='./book/src/images/*' \
	--skip='./docs/*,./.git' \
	--skip='*.svg' \
	--skip='*.br' \
	--skip='./rlm_python/mods-available/eap' \
	--skip='./server/lib/src/constants/system_config.rs' \
	--skip='./pykanidm/site'

.PHONY: test/pykanidm/pytest
test/pykanidm/pytest: ## python library testing
	cd pykanidm && \
	uv run pytest -vv

.PHONY: test/pykanidm/lint
test/pykanidm/lint: ## python library linting
	cd pykanidm && \
	uv run ruff check tests kanidm

.PHONY: test/pykanidm/mypy
test/pykanidm/mypy: ## python library type checking
	cd pykanidm && \
	uv run mypy --strict tests kanidm

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
	find . -type f  \
		-not -path './target/*' \
		-not -path './docs/*' \
		-not -path '*/.venv/*' -not -path './vendor/*'\
		-not -path '*/.*/*' \
		-name \*.md \
		-exec deno fmt --check $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Kanidm book
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' -not -path './vendor/*'\
		-name \*.md \
		-exec deno fmt  $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: book
book: ## Build the Kanidm book
book:
	echo "Building rust docs"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mv ./book/book/ ./docs/
	mkdir -p $(PWD)/docs/rustdoc/${BOOK_VERSION}/
	rsync -a --delete $(PWD)/target/doc/ $(PWD)/docs/rustdoc/${BOOK_VERSION}/

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
	uv run --group docs mkdocs build

.PHONY: docs/pykanidm/serve
docs/pykanidm/serve: ## Run the local mkdocs server
docs/pykanidm/serve:
	cd pykanidm && \
	uv run --group docs mkdocs serve

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


.PHONY: coverage
coverage: ## Run the coverage tests using cargo-tarpaulin
	cargo tarpaulin --out Html
	@echo "Coverage file at file://$(PWD)/tarpaulin-report.html"


.PHONY: coveralls
coveralls: ## Run cargo tarpaulin and upload to coveralls
coveralls:
	cargo tarpaulin --coveralls $(COVERALLS_REPO_TOKEN)
	@echo "Coveralls repo information is at https://coveralls.io/github/kanidm/kanidm"


.PHONY: eslint
eslint: ## Run eslint on the UI javascript things
eslint: eslint/setup
	@echo "################################"
	@echo "   Running eslint..."
	@echo "################################"
	cd server/core && find ./static -name '*js' -not -path '*/external/*' -exec eslint "{}" \;
	@echo "################################"
	@echo "Done!"

.PHONY: eslint/setup
eslint/setup: ## Install eslint for the UI javascript things
	cd server/core && npm ci

.PHONY: prettier
prettier: ## Run prettier on the UI javascript things
prettier: eslint/setup
	@echo "   Running prettier..."
	cd server/core && npm run prettier
	@echo "Done!"

.PHONY: prettier/fix
prettier/fix: ## Run prettier on the UI javascript things and write back changes
prettier/fix: eslint/setup
	@echo "   Running prettier..."
	cd server/core && npm run prettier:fix
	@echo "Done!"

.PHONY: publish
publish: ## Publish to crates.io
publish:
	cargo publish -p scim_proto
	cargo publish -p kanidm_build_profiles
	cargo publish -p kanidm_proto
	cargo publish -p sketching
	cargo publish -p kanidm_utils_users
	cargo publish -p kanidm_lib_file_permissions
	cargo publish -p kanidm_lib_crypto
	cargo publish -p kanidm_client
	cargo publish -p kanidm_tools

.PHONY: rust_container
rust_container: # Build and run a container based on the Linux rust base container, with our requirements included
rust_container:
	docker build --pull -t kanidm_rust -f scripts/Dockerfile.devcontainer .
	docker run \
		--rm -it \
		--name kanidm \
		--mount type=bind,source=$(PWD),target=/kanidm -w /kanidm kanidm_rust:latest
