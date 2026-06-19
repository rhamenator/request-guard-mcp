.PHONY: build test fmt clippy audit deny clean docker-build docker-run

# ─── Build ──────────────────────────────────────────────────────────────────
build:
	cargo build --release

build-dev:
	cargo build

# ─── Tests ──────────────────────────────────────────────────────────────────
test:
	cargo test --all-features

test-verbose:
	cargo test --all-features -- --nocapture

# ─── Lint / Format ──────────────────────────────────────────────────────────
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# ─── Security ────────────────────────────────────────────────────────────────
audit:
	cargo audit

deny:
	cargo deny check

# ─── Local run ───────────────────────────────────────────────────────────────
run:
	cargo run

run-release:
	cargo run --release

# ─── Docker ──────────────────────────────────────────────────────────────────
docker-build:
	docker build -t ai-scraping-defense-mcp:local -f docker/Dockerfile .

docker-run: docker-build
	docker run --rm -p 8085:8085 \
		-e AUTH_TOKENS=dev-token \
		-e LOG_LEVEL=debug \
		ai-scraping-defense-mcp:local

docker-compose-up:
	docker compose -f docker/docker-compose.yml up -d

docker-compose-down:
	docker compose -f docker/docker-compose.yml down

# ─── Kubernetes ──────────────────────────────────────────────────────────────
k8s-apply:
	kubectl apply -f deploy/k8s/namespace.yaml
	kubectl apply -f deploy/k8s/configmap.yaml
	kubectl apply -f deploy/k8s/deployment.yaml
	kubectl apply -f deploy/k8s/service.yaml
	kubectl apply -f deploy/k8s/hpa.yaml
	kubectl apply -f deploy/k8s/networkpolicy.yaml

k8s-delete:
	kubectl delete -f deploy/k8s/ --ignore-not-found

# ─── Misc ────────────────────────────────────────────────────────────────────
clean:
	cargo clean

ci: fmt-check clippy test audit deny
