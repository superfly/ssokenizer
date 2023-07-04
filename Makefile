.PHONY: vendor
vendor: go.mod go.sum
	go mod vendor

.PHONY: deploy
deploy: vendor
	fly deploy --build-arg SSOKENIZER_VERSION=0.0.1 --build-arg SSOKENIZER_COMMIT=$(shell git rev-parse HEAD)