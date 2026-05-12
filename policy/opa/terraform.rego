# Conftest/OPA policy for Terraform (HCL) in deploy/terraform/.
# Evidence: SC-28 (encryption at rest), SC-8 (transmission), AC-3/AC-6 (access), AU-2/AU-12
# (logging), CM-6 (secure settings). This is intentionally a small, illustrative set — extend
# with your cloud's required controls (the cloud-provider Cloud Computing SRG impact-level
# requirements, CNSSI 1253 baselines, your org overlays).
#
# Conftest parses HCL into a JSON shape under `input.resource.<type>.<name>`.

package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# --- DENY: S3 buckets must block public access ------------------------------------------------
deny contains msg if {
	some name, _ in input.resource.aws_s3_bucket
	not input.resource.aws_s3_bucket_public_access_block[name]
	msg := sprintf("[AC-3] aws_s3_bucket.%s: missing an aws_s3_bucket_public_access_block resource", [name])
}

deny contains msg if {
	some name, cfg in input.resource.aws_s3_bucket_public_access_block
	not cfg.block_public_acls == true
	msg := sprintf("[AC-3] aws_s3_bucket_public_access_block.%s: block_public_acls must be true", [name])
}

# --- WARN: S3 default encryption --------------------------------------------------------------
warn contains msg if {
	some name, _ in input.resource.aws_s3_bucket
	not input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
	msg := sprintf("[SC-28] aws_s3_bucket.%s: define server-side encryption (SSE-KMS preferred)", [name])
}

# --- WARN: versioning on storage --------------------------------------------------------------
warn contains msg if {
	some name, _ in input.resource.aws_s3_bucket
	not input.resource.aws_s3_bucket_versioning[name]
	msg := sprintf("[CP-9/SI-7] aws_s3_bucket.%s: enable versioning (backup/integrity)", [name])
}

# --- DENY: security groups must not allow 0.0.0.0/0 to sensitive ports ------------------------
sensitive_ports := {22, 3389, 3306, 5432, 6379, 27017, 9200, 1433}

deny contains msg if {
	some name, sg in input.resource.aws_security_group
	some ingress in array.concat([], object.get(sg, "ingress", []))
	"0.0.0.0/0" in object.get(ingress, "cidr_blocks", [])
	from := object.get(ingress, "from_port", 0)
	from in sensitive_ports
	msg := sprintf("[SC-7/CM-7] aws_security_group.%s: ingress from 0.0.0.0/0 to port %d is not permitted", [name, from])
}

# --- WARN: encrypt EBS / RDS storage ----------------------------------------------------------
warn contains msg if {
	some name, vol in input.resource.aws_ebs_volume
	not vol.encrypted == true
	msg := sprintf("[SC-28] aws_ebs_volume.%s: encrypted must be true", [name])
}

warn contains msg if {
	some name, db in input.resource.aws_db_instance
	not db.storage_encrypted == true
	msg := sprintf("[SC-28] aws_db_instance.%s: storage_encrypted must be true", [name])
}

# --- WARN: enable logging ---------------------------------------------------------------------
warn contains msg if {
	some name, _ in input.resource.aws_s3_bucket
	not input.resource.aws_s3_bucket_logging[name]
	msg := sprintf("[AU-2/AU-12] aws_s3_bucket.%s: enable access logging", [name])
}

# --- DENY: no plaintext hardcoded credentials in variables/defaults ---------------------------
deny contains msg if {
	some name, v in input.variable
	is_string(v["default"])
	regex.match(`(?i)(secret|password|token|api[_-]?key)`, name)
	count(v["default"]) > 0
	msg := sprintf("[IA-5] variable.%s: do not set a default value for a secret variable — source it from a secrets manager", [name])
}
