#!/bin/bash

export CARGO_TARGET_DIR="${TMPDIR}cargo_target"
DOCS_DIR="${TMPDIR}docs"

function build_version() {
    BOOK_VERSION=$1
    echo "Book version: ${BOOK_VERSION}"
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build kanidm_book
	mv ./kanidm_book/book/ "${DOCS_DIR}/${BOOK_VERSION}/"
	mkdir -p "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
	mv ./target/doc/* "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
}

mkdir -p "${DOCS_DIR}"

for version in $(git tag -l | grep -E '^v' | head -n2); do
    echo "$version"
    build_version "${version}"
done

ls -la "${DOCS_DIR}"