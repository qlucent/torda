# Torda benchmark harness — top-level entrypoints (spec §9).
# `make selftest` needs no Docker/agent and proves the scoring loop; the `bench-*`
# targets run against privileged Linux targets (validated on a real host / GCP VM).

SHELL := /bin/bash
IMAGE_UBUNTU ?= torda-bench-ubuntu
IMAGE_ROCKY  ?= torda-bench-rocky
TORDA_REF    ?= main
SINK         ?= /var/log/torda/bench.ndjson
RESULTS_ROOT ?= results
BTF          ?= /sys/kernel/btf/vmlinux
DOCKER_RUN   = docker run --rm --privileged --pid=host \
                 -v $(BTF):$(BTF):ro -v "$(PWD)/$(RESULTS_ROOT):/src/torda/bench/$(RESULTS_ROOT)"

.PHONY: help selftest bootstrap bench-linux bench-rocky bench-wazuh \
        bench-vuln bench-footprint bench-windows report

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

selftest: ## Prove the capture->score->report loop WITHOUT a live agent (cargo test)
	cargo test -p torda-bench

bootstrap: ## Build target images (clone+build torda + torda-bench, drop ISOLATED sentinel)
	docker build -f images/ubuntu-target.Dockerfile --build-arg TORDA_REF=$(TORDA_REF) -t $(IMAGE_UBUNTU) .
	docker build -f images/rocky-target.Dockerfile  --build-arg TORDA_REF=$(TORDA_REF) -t $(IMAGE_ROCKY)  .

bench-linux: ## Full Linux suite (coverage + latency + conformance) on the ubuntu target
	$(DOCKER_RUN) $(IMAGE_UBUNTU) bash -lc 'SINK=$(SINK) bash scripts/bench_entry.sh'

bench-rocky: ## Same suite on the rpm target (release-aware OSV path)
	$(DOCKER_RUN) $(IMAGE_ROCKY) bash -lc 'SINK=$(SINK) bash scripts/bench_entry.sh'

report: ## Print the newest run's report.md
	@latest=$$(ls -1dt $(RESULTS_ROOT)/*/ 2>/dev/null | head -1); \
	  [ -n "$$latest" ] && cat "$$latest/report.md" || echo "no results yet — run make bench-linux"

bench-wazuh: ## Peer parity run on an identical image (spec §5, build-order §11.4)
	@echo "TODO §11.4: install Wazuh + stock ruleset on an identical image, replay the"
	@echo "registry, normalize alerts.json -> captures.json (agent=wazuh), score with the"
	@echo "SAME 'torda-bench score', emit the side-by-side matrix."

bench-vuln: ## SBOM -> findings vs grype/trivy (spec §7, build-order §11.7)
	@echo "TODO §11.7: future 'torda-bench vuln' subcommand — torda findings + grype + trivy"
	@echo "per pinned image; precision/recall + KEV-ordering + release-aware + fix-grouping."

bench-footprint: ## Load test cpu/mem/dropped-event % vs osquery (spec §6.3, build-order §11.8)
	@echo "TODO §11.8: future 'torda-bench footprint' subcommand — loadgen at 1k/10k/100k eps,"
	@echo "sample cpu/RSS (sysinfo), compute dropped-event %, repeat vs osquery."

bench-windows: ## ETW subset (spec §8, build-order §11.9)
	@echo "TODO §11.9: provision a Windows target, build --features windows-etw, run the"
	@echo "atomics/windows subset through the SAME scoring path."
