
docker-kanidmd:
	docker build -f kanidmd/Dockerfile -t kanidm/server:latest .

docker-radiusd:
	docker build -f kanidm_rlm_python/Dockerfile -t kanidm/radius:latest kanidm_rlm_python

vendor-prep:
	cargo vendor
	tar -czf vendor.tar.gz vendor

doc-local:
	cargo doc --document-private-items

install-tools-local:
	cd kanidm_tools && cargo install --path . --force

prep:
	cargo outdated -R
	cargo audit
