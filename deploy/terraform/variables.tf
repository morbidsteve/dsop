variable "region" {
  description = "Cloud region (use a region authorized for your impact level / DoD cloud)."
  type        = string
  default     = "us-gov-west-1"
}

variable "system_name" {
  description = "System name (matches the SSP / eMASS system record)."
  type        = string
  default     = "dsop-reference-system"
}

variable "environment" {
  description = "Deployment environment (dev | test | staging | prod) — RAISE expects multi-tier."
  type        = string
  default     = "dev"
}

variable "data_owner" {
  description = "Data owner / responsible organization."
  type        = string
  default     = "your-program-office"
}

variable "log_bucket_name" {
  description = "Name of the S3 bucket used for application/access logs."
  type        = string
  default     = "dsop-reference-system-logs"
}

variable "artifact_bucket_name" {
  description = "Name of the S3 bucket used to store build artifacts / evidence (immutable archive)."
  type        = string
  default     = "dsop-reference-system-artifacts"
}

variable "kms_key_arn" {
  description = "ARN of the (FIPS-validated) KMS CMK used for encryption at rest (SC-13/SC-28)."
  type        = string
  default     = "" # set to your CMK; example resource below creates one if empty
}
