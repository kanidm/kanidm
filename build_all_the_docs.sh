#!/bin/bash

export CARGO_TARGET_DIR="${TMPDIR}cargo_target"
DOCS_DIR="/tmp/kanidm_docs"

echo "DOCS DIR: ${DOCS_DIR}"
echo "PWD: $(pwd)"

function build_version() {
    BOOK_VERSION=$1
    echo "Book version: ${BOOK_VERSION}"
    echo "<li><a href=\"/${BOOK_VERSION}\">${BOOK_VERSION}</a></li>" >> "${DOCS_DIR}/index.html"
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	RUSTFLAGS=-Awarnings cargo doc --quiet --no-deps
	mdbook build kanidm_book
	mv ./kanidm_book/book/ "${DOCS_DIR}/${BOOK_VERSION}/"
	mkdir -p "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
	mv ./target/doc/* "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
}

mkdir -p "${DOCS_DIR}"

cat > "${DOCS_DIR}/index.html" <<-'EOM'
<html>
<head>
<title>kanidm docs root</title>
</head>
<body>
<h1>Kanidm docs</h1>
<ul>
EOM


build_version master

for version in $(git tag -l 'v*' --sort "-version:refname" | grep -v '1.1.0alpha'); do
    echo "$version"
    build_version "${version}"
done


cat >> "${DOCS_DIR}/index.html" <<-'EOM'

</ul>
</body>
</html>
EOM
ls -la "${DOCS_DIR}"

mv "${DOCS_DIR}" ./docs/