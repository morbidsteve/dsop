# Conftest/OPA policy for Dockerfiles. Evidence: CM-6 (secure settings), CM-7 (least
# functionality), AC-6 (least privilege), SI-7/SR-4 (provenance labels); NIST SP 800-190; DoD/DISA
# Container Hardening Process Guide; RAISE 2.0 container hardening expectations.
#
# Run with the dockerfile parser:
#   conftest test sample-app/Dockerfile --parser dockerfile --policy policy/opa
# (The pipeline's iac-scan job tests deploy/k8s and deploy/terraform; add the Dockerfile here too
#  if you want this policy enforced as a control gate.)
#
# Conftest's dockerfile parser yields a flat array of instructions: [{Cmd: "from", Value: [...]}, ...].
# `deny` rules are build-blocking (policy/thresholds.yaml: gates.iac.fail_on_conftest_deny);
# `warn` rules are recorded as findings / POA&M candidates.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Only act on Dockerfile input (Conftest's dockerfile parser yields an array of {Cmd,Value}
# objects). For any other input shape (k8s YAML, Terraform HCL, etc.) these rules stay silent so a
# single `conftest test` over a mixed tree doesn't misfire.
is_dockerfile if {
	is_array(input)
	some v in input
	is_object(v)
	v.Cmd
}

# Lower-cased instruction values for a given Docker command (e.g., "from", "user", "run").
instr_values(cmd) := [lower(concat(" ", v.Value)) |
	some v in input
	is_object(v)
	lower(v.Cmd) == cmd
]

# These are only DEFINED when the input is a Dockerfile, so every rule below is implicitly
# gated — for any other input shape they're undefined and the rules simply don't fire.
users := instr_values("user") if is_dockerfile
froms := instr_values("from") if is_dockerfile
healthchecks := instr_values("healthcheck") if is_dockerfile
labels := instr_values("label") if is_dockerfile
adds := instr_values("add") if is_dockerfile
runs := instr_values("run") if is_dockerfile

last_user := users[count(users) - 1] if count(users) > 0

# --- DENY: a non-root USER must be set (and not be root/uid 0) --------------------------------
deny contains "[CM-6/AC-6] Dockerfile: no USER instruction — image runs as root. Add a non-root USER before CMD/ENTRYPOINT." if {
	count(users) == 0
}

deny contains sprintf("[CM-6/AC-6] Dockerfile: final USER is %q (root) — switch to a non-root user.", [last_user]) if {
	count(users) > 0
	last_user in {"root", "0", "0:0"}
}

# --- DENY: a HEALTHCHECK must be present (or wired via the orchestrator probe — confirm) -------
deny contains "[SI-4/CM-6] Dockerfile: no HEALTHCHECK instruction (confirm a runtime/orchestrator probe is configured instead — see deploy/k8s/)." if {
	count(healthchecks) == 0
}

# --- WARN: pin the base image (no :latest; prefer a digest) -----------------------------------
warn contains sprintf("[CM-2] Dockerfile FROM %q: don't use ':latest' — pin a version, ideally by digest (@sha256:...).", [f]) if {
	some f in froms
	contains(f, ":latest")
}

warn contains sprintf("[CM-2] Dockerfile FROM %q: base image is not version-pinned.", [f]) if {
	some f in froms
	not contains(f, ":")
	not contains(f, "@sha256:")
	not contains(f, "scratch")
}

# --- WARN: prefer a DoD-hardened base image (Iron Bank / Repo One) -----------------------------
warn contains sprintf("[SR-3/CM-6] Dockerfile FROM %q: consider a DoD-hardened base image (Iron Bank / Repo One: registry1.dso.mil) or your program's approved base-image source.", [f]) if {
	some f in froms
	not contains(f, "ironbank")
	not contains(f, "registry1.dso.mil")
	not contains(f, "scratch")
}

# --- WARN: don't ADD remote URLs; COPY a vendored, checksum-verified artifact instead ----------
warn contains sprintf("[SR-3] Dockerfile ADD %q: fetching over the network during the build is risky — vendor the artifact and COPY it with a verified checksum.", [a]) if {
	some a in adds
	regex.match(`https?://`, a)
}

# --- WARN: minimize the image (apt --no-install-recommends + clean lists) ----------------------
warn contains "[CM-7] Dockerfile RUN: use `apt-get install --no-install-recommends` and clean `/var/lib/apt/lists/*` to minimize the image (least functionality)." if {
	some r in runs
	contains(r, "apt-get install")
	not contains(r, "--no-install-recommends")
}

# --- WARN: declare OCI provenance labels ------------------------------------------------------
has_source_label if {
	some l in labels
	contains(l, "org.opencontainers.image.source")
}

warn contains "[SI-7/SR-4] Dockerfile: add OCI provenance LABELs (org.opencontainers.image.source/revision/version) to aid traceability." if {
	is_dockerfile
	not has_source_label
}
