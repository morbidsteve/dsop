# Conftest/OPA policy for Kubernetes manifests in deploy/k8s/.
# Evidence: CM-6 (secure settings), CM-7 (least functionality), AC-6 (least privilege),
# SC-7 (boundary protection via NetworkPolicy), SI-7 (immutability); NIST SP 800-190; DISA
# Kubernetes STIG / Container Platform SRG themes.
#
# `deny` rules are build-blocking (policy/thresholds.yaml: gates.iac.fail_on_conftest_deny).
# `warn` rules are recorded as findings / POA&M candidates. Each `conftest test` invocation runs
# these `package main` rules against every YAML document; the rules are gated so they only act on
# the kinds they understand.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}

is_workload if {
	is_object(input)
	input.kind in workload_kinds
}

# Pull the pod spec regardless of workload kind.
pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"
pod_spec := input.spec if input.kind == "Pod"

all_containers := array.concat(
	object.get(pod_spec, "containers", []),
	object.get(pod_spec, "initContainers", []),
) if is_workload

cname(c) := object.get(c, "name", "?")
csc(c) := object.get(c, "securityContext", {})

# --- DENY: must run as non-root (pod-level OR container-level) ---------------------------------
deny contains msg if {
	is_workload
	not pod_spec.securityContext.runAsNonRoot == true
	some c in all_containers
	not csc(c).runAsNonRoot == true
	msg := sprintf("[CM-6/AC-6] %s/%s: container %q must set securityContext.runAsNonRoot=true (pod- or container-level).", [input.kind, input.metadata.name, cname(c)])
}

# --- DENY: no privileged containers -----------------------------------------------------------
deny contains msg if {
	is_workload
	some c in all_containers
	csc(c).privileged == true
	msg := sprintf("[CM-7/AC-6] %s/%s: container %q is privileged — not permitted.", [input.kind, input.metadata.name, cname(c)])
}

# --- DENY: no privilege escalation ------------------------------------------------------------
deny contains msg if {
	is_workload
	some c in all_containers
	not csc(c).allowPrivilegeEscalation == false
	msg := sprintf("[AC-6] %s/%s: container %q must set allowPrivilegeEscalation=false.", [input.kind, input.metadata.name, cname(c)])
}

# --- DENY: drop ALL Linux capabilities --------------------------------------------------------
deny contains msg if {
	is_workload
	some c in all_containers
	drops := {d | some d in object.get(object.get(csc(c), "capabilities", {}), "drop", [])}
	not "ALL" in drops
	msg := sprintf("[CM-7] %s/%s: container %q must drop ALL capabilities (securityContext.capabilities.drop: [ALL]).", [input.kind, input.metadata.name, cname(c)])
}

# --- DENY: image must be version-pinned -------------------------------------------------------
deny contains msg if {
	is_workload
	some c in all_containers
	img := object.get(c, "image", "")
	not contains(img, ":")
	not contains(img, "@sha256:")
	msg := sprintf("[CM-2] %s/%s: container %q image %q is not version-pinned.", [input.kind, input.metadata.name, cname(c), img])
}

# --- DENY: no hostNetwork ---------------------------------------------------------------------
deny contains msg if {
	is_workload
	pod_spec.hostNetwork == true
	msg := sprintf("[SC-7] %s/%s: hostNetwork is not permitted.", [input.kind, input.metadata.name])
}

# --- DENY: no hostPath volumes ----------------------------------------------------------------
deny contains msg if {
	is_workload
	some v in object.get(pod_spec, "volumes", [])
	v.hostPath
	msg := sprintf("[CM-7] %s/%s: hostPath volume %q is not permitted.", [input.kind, input.metadata.name, object.get(v, "name", "?")])
}

# --- WARN: read-only root filesystem ----------------------------------------------------------
warn contains msg if {
	is_workload
	some c in all_containers
	not csc(c).readOnlyRootFilesystem == true
	msg := sprintf("[SI-7] %s/%s: container %q should set readOnlyRootFilesystem=true.", [input.kind, input.metadata.name, cname(c)])
}

# --- WARN: memory limit set -------------------------------------------------------------------
warn contains msg if {
	is_workload
	some c in all_containers
	not object.get(object.get(object.get(c, "resources", {}), "limits", {}), "memory", false)
	msg := sprintf("[SC-6/CM-6] %s/%s: container %q has no memory limit (DoS resilience).", [input.kind, input.metadata.name, cname(c)])
}

# --- WARN: don't use :latest ------------------------------------------------------------------
warn contains msg if {
	is_workload
	some c in all_containers
	endswith(object.get(c, "image", ""), ":latest")
	msg := sprintf("[CM-2] %s/%s: container %q uses an unpinned ':latest' image — pin a tag, ideally a digest.", [input.kind, input.metadata.name, cname(c)])
}

# --- WARN: seccomp profile --------------------------------------------------------------------
warn contains msg if {
	is_workload
	not object.get(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type", false)
	msg := sprintf("[CM-6] %s/%s: set securityContext.seccompProfile.type (RuntimeDefault or Localhost).", [input.kind, input.metadata.name])
}

# --- WARN: automountServiceAccountToken should be false unless needed --------------------------
warn contains msg if {
	is_workload
	not pod_spec.automountServiceAccountToken == false
	msg := sprintf("[AC-6] %s/%s: set automountServiceAccountToken=false unless the workload needs the API.", [input.kind, input.metadata.name])
}

# --- WARN: namespaces should have a default-deny NetworkPolicy --------------------------------
warn contains msg if {
	is_object(input)
	input.kind == "Namespace"
	msg := sprintf("[SC-7] Namespace %q: ensure a default-deny NetworkPolicy is applied (boundary protection).", [input.metadata.name])
}
