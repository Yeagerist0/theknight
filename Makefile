.PHONY: build test lint vet fmt clean run localstack-up localstack-down integration-test

LOCALSTACK_CONTAINER := theknight-localstack
LOCALSTACK_IMAGE := localstack/localstack:3.8.1

build:
	go build -o bin/theknight ./cmd/theknight

run: build
	./bin/theknight

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: fmt vet

clean:
	rm -rf bin/

# localstack-up/integration-test require Docker. Unit tests (`make test`)
# never need it — this is a separate, slower tier that exercises real AWS
# SDK request/response wiring against an emulated backend instead of the
# hand-rolled fakes pkg/scanner's unit tests use.
#
# Pinned below 4.x: newer LocalStack builds fail fast with "License
# activation failed" when no LOCALSTACK_AUTH_TOKEN is set, even for the
# core services (S3/IAM/EC2) this suite only needs. 3.8.1 is confirmed to
# start clean with zero config.
localstack-up:
	docker run -d --rm --name $(LOCALSTACK_CONTAINER) -p 4566:4566 $(LOCALSTACK_IMAGE)
	@echo "waiting for LocalStack..."
	@for i in $$(seq 1 30); do \
		if ! docker ps --filter name=$(LOCALSTACK_CONTAINER) --filter status=running -q | grep -q .; then \
			echo "LocalStack container exited unexpectedly:"; \
			docker logs $(LOCALSTACK_CONTAINER) 2>&1 | tail -20; \
			exit 1; \
		fi; \
		if curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; then \
			echo "LocalStack ready"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "LocalStack did not become ready within 30s"; \
	docker logs $(LOCALSTACK_CONTAINER) 2>&1 | tail -20; \
	exit 1

localstack-down:
	docker stop $(LOCALSTACK_CONTAINER) >/dev/null 2>&1 || true

integration-test: localstack-up
	go test -tags=integration ./pkg/scanner/... -v; \
	status=$$?; \
	$(MAKE) localstack-down; \
	exit $$status
