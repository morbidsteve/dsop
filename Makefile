# DSOP — local pipeline. `make help` lists targets. CI (.github/workflows/devsecops-pipeline.yml)
# is authoritative; this is for pre-flight. Most targets degrade gracefully if a tool is missing.

SHELL := /bin/bash
IMAGE ?= dsop/sample-app:local
RAW   ?= raw-evidence
EV    ?= evidence
PY    ?= python3

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: tools
tools: ## Print install hints for the local scanners
	@echo "Install (versions pinned in CI; latest is fine locally):"
	@echo "  pip install -r sample-app/requirements-dev.txt -r scripts/requirements.txt semgrep checkov"
	@echo "  brew install trivy grype syft gitleaks trufflehog hadolint dockle conftest kube-linter cosign  # or your distro's equivalents"
	@echo "  docker (for build/scan/DAST)  •  oscap / openscap-scanner (for STIG/SCAP)"
	@echo "  KICS, OWASP Dependency-Check, OWASP ZAP — run via container (see CI workflow)"

# --- build / test --------------------------------------------------------------------------------
.PHONY: deps
deps: ## Install Python deps (app + tooling)
	$(PY) -m pip install -q -r sample-app/requirements-dev.txt -r scripts/requirements.txt

.PHONY: test
test: deps ## Run unit tests + coverage
	cd sample-app && pytest --cov=app --cov-report=term --cov-report=xml --junitxml=../$(RAW)/build-test/test-results.xml

.PHONY: build
build: ## Build the container image
	docker build -t $(IMAGE) sample-app

# --- security gates (write raw outputs under $(RAW)/) --------------------------------------------
.PHONY: gates
gates: sast sca sbom secrets iac license container dast stig ## Run all security gates (best effort)

mkraw = mkdir -p $(RAW)/$(1)

.PHONY: sast
sast: ## SAST — Semgrep (CodeQL runs in CI only)
	@$(call mkraw,evidence-sast); command -v semgrep >/dev/null && semgrep --config p/security-audit --config p/owasp-top-ten --config ./policy/semgrep/dod-secure-coding.yml --sarif -o $(RAW)/evidence-sast/semgrep.sarif . || echo "semgrep not installed — skipping"

.PHONY: sca
sca: ## SCA — Trivy fs + Grype
	@$(call mkraw,evidence-sca); command -v trivy >/dev/null && trivy fs --config policy/trivy/trivy.yaml -f json -o $(RAW)/evidence-sca/trivy-fs.json . || echo "trivy not installed — skipping"
	@command -v grype >/dev/null && grype dir:. -o json > $(RAW)/evidence-sca/grype-fs.json || echo "grype not installed — skipping"

.PHONY: sbom
sbom: ## SBOM — Syft -> SPDX + CycloneDX
	@$(call mkraw,evidence-sbom); command -v syft >/dev/null && { syft . -o spdx-json=$(RAW)/evidence-sbom/sbom-source.spdx.json; syft . -o cyclonedx-json=$(RAW)/evidence-sbom/sbom-source.cdx.json; } || echo "syft not installed — skipping"

.PHONY: secrets
secrets: ## Secrets — Gitleaks
	@$(call mkraw,evidence-secrets); command -v gitleaks >/dev/null && gitleaks detect --config policy/gitleaks/.gitleaks.toml --report-format json --report-path $(RAW)/evidence-secrets/gitleaks-report.json || echo "gitleaks not installed (or no leaks) — continuing"

.PHONY: iac
iac: ## IaC — Checkov + Trivy config + Conftest/OPA
	@$(call mkraw,evidence-iac); command -v checkov >/dev/null && checkov -d . --config-file policy/checkov/.checkov.yaml -o json > $(RAW)/evidence-iac/checkov.json || echo "checkov not installed — skipping"
	@command -v trivy >/dev/null && trivy config . -f json -o $(RAW)/evidence-iac/trivy-config.json || true
	@command -v conftest >/dev/null && { conftest test deploy/k8s --policy policy/opa -o json > $(RAW)/evidence-iac/conftest-k8s.json || true; conftest test deploy/terraform --policy policy/opa -o json > $(RAW)/evidence-iac/conftest-tf.json || true; } || echo "conftest not installed — skipping"

.PHONY: license
license: deps sbom ## License policy check (needs the CycloneDX SBOM)
	@$(call mkraw,evidence-license); test -f $(RAW)/evidence-sbom/sbom-source.cdx.json && $(PY) scripts/evidence_common.py --check-licenses $(RAW)/evidence-sbom/sbom-source.cdx.json policy/allowed-licenses.yaml --out $(RAW)/evidence-license/license-report.json || echo "no CycloneDX SBOM — run 'make sbom' first"

.PHONY: container
container: build ## Container — Trivy/Grype image scan + Hadolint + Syft image SBOM
	@$(call mkraw,evidence-container); command -v hadolint >/dev/null && hadolint -f sarif sample-app/Dockerfile > $(RAW)/evidence-container/hadolint.sarif || true
	@command -v trivy >/dev/null && trivy image --config policy/trivy/trivy.yaml -f json -o $(RAW)/evidence-container/trivy-image.json $(IMAGE) || echo "trivy not installed — skipping"
	@command -v grype >/dev/null && grype $(IMAGE) -o json > $(RAW)/evidence-container/grype-image.json || true
	@command -v syft >/dev/null && { syft $(IMAGE) -o spdx-json=$(RAW)/evidence-container/sbom-image.spdx.json; syft $(IMAGE) -o cyclonedx-json=$(RAW)/evidence-container/sbom-image.cdx.json; } || true

.PHONY: dast
dast: build ## DAST — OWASP ZAP baseline against the running container (via Docker)
	@$(call mkraw,evidence-dast); docker rm -f dsop-dast >/dev/null 2>&1 || true; docker run -d --name dsop-dast -p 8080:8080 $(IMAGE) >/dev/null; \
	 for i in $$(seq 1 20); do curl -sf http://localhost:8080/healthz >/dev/null && break || sleep 1; done; \
	 docker run --rm --network host -v $$PWD/$(RAW)/evidence-dast:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:8080 -J zap-report.json -c /zap/wrk/../../policy/zap/rules.tsv || true; \
	 docker rm -f dsop-dast >/dev/null 2>&1 || true

.PHONY: stig
stig: ## STIG/SCAP — OpenSCAP eval (placeholder; supply your DISA SCAP content — see docs/pipeline-gates.md)
	@$(call mkraw,evidence-stig); echo "Supply your DISA STIG/SRG SCAP content and run 'oscap xccdf eval' here — see docs/pipeline-gates.md (#stig)." > $(RAW)/evidence-stig/README.txt

# --- evidence assembly ---------------------------------------------------------------------------
.PHONY: evidence
evidence: deps ## Aggregate $(RAW)/ -> $(EV)/ (findings, controls, POA&M, ConMon, eMASS package, dashboard data)
	@test -d $(RAW) || { echo "No $(RAW)/ — run 'make gates' first (or populate $(RAW)/ from a CI run)."; exit 1; }
	$(PY) scripts/aggregate_evidence.py --input $(RAW) --out $(EV) --run-url "local"
	$(PY) scripts/map_controls.py --evidence $(EV) --catalog compliance/control-catalog/control-catalog.yaml --out $(EV)/boe
	$(PY) scripts/generate_poam.py --evidence $(EV) --thresholds policy/thresholds.yaml --out $(EV)/boe
	$(PY) scripts/update_conmon.py --evidence $(EV) --history $(EV)/boe/conmon_history.json --commit "$$(git rev-parse HEAD 2>/dev/null || echo local)" --run-id local
	$(PY) scripts/build_emass_package.py --evidence $(EV) --catalog compliance/control-catalog/control-catalog.yaml --ssp compliance/ssp/system-security-plan.md --out $(EV)/emass-package
	$(PY) scripts/build_dashboard_data.py --evidence $(EV) --catalog compliance/control-catalog/control-catalog.yaml --site site --repo "$$(git config --get remote.origin.url 2>/dev/null | sed -E 's#.*[:/]([^/]+/[^/.]+)(\.git)?$$#\1#')" --ref "$$(git branch --show-current 2>/dev/null)" --sha "$$(git rev-parse HEAD 2>/dev/null)" --run-url local
	@echo "Evidence in $(EV)/ ; eMASS package in $(EV)/emass-package/ ; dashboard data in site/data/"

.PHONY: site
site: ## Serve the dashboard locally (http://localhost:8000)
	@echo "Serving site/ at http://localhost:8000 (Ctrl-C to stop)"; cd site && $(PY) -m http.server 8000

.PHONY: scan
scan: gates evidence ## Run all gates + assemble the evidence (the full local pipeline)

.PHONY: clean
clean: ## Remove generated artifacts
	rm -rf $(RAW) $(EV) sample-app/coverage.xml .pytest_cache .ruff_cache; find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Note: site/data/*.json are committed seeds — regenerate with 'make evidence' or restore from git."
