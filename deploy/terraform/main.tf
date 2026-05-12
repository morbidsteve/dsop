# ------------------------------------------------------------------------------------------------
# EXAMPLE infrastructure-as-code — intentionally small, written to PASS the IaC gate (Checkov /
# KICS / Trivy-config / Conftest-OPA) so it demonstrates "secure by default" IaC. Replace with
# your real infrastructure. Controls demonstrated: SC-28 (encryption at rest), SC-13 (FIPS crypto),
# AC-3 (no public access), AU-2/AU-12 (logging), CP-9/SI-7 (versioning), CM-6 (secure settings).
#
# NOTE: This is for scanning demonstration; `terraform plan/apply` is not run by the pipeline.
# ------------------------------------------------------------------------------------------------

# A CMK for encryption at rest if the caller didn't supply one.
resource "aws_kms_key" "this" {
  count                   = var.kms_key_arn == "" ? 1 : 0
  description             = "${var.system_name} encryption key (encrypt data at rest — SC-28/SC-13)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

locals {
  kms_arn = var.kms_key_arn != "" ? var.kms_key_arn : aws_kms_key.this[0].arn
}

# ---- Access-log bucket -------------------------------------------------------------------------
resource "aws_s3_bucket" "logs" {
  bucket = var.log_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "retain-and-expire"
    status = "Enabled"
    noncurrent_version_expiration { noncurrent_days = 365 }
    expiration { days = 730 } # tune to your records-retention requirement (AU-11)
  }
}

# ---- Artifact / evidence archive bucket --------------------------------------------------------
resource "aws_s3_bucket" "artifacts" {
  bucket = var.artifact_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" } # immutable-ish archive of releases/evidence (SI-7, CP-9)
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/${var.artifact_bucket_name}/"
}

# Enforce TLS-only access (SC-8): deny any request not using HTTPS.
data "aws_iam_policy_document" "artifacts_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts_tls_only.json
}

output "kms_key_arn" {
  value = local.kms_arn
}
output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}
