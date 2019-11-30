
docker-kanidmd:
	docker build -f kanidmd/Dockerfile -t kanidmd:latest .

docker-radiusd:
	docker build -f kanidm_rlm_python/Dockerfile -t kanidm_radius:latest kanidm_rlm_python

vendor-prep:
	cargo vendor
	tar -czf vendor.tar.gz vendor

