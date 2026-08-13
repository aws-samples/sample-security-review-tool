## Scenario 1: missing-query-result-encryption
## No encryption_option specified in the encryption_configuration block.
resource "aws_athena_workgroup" "missing_encryption" {
  name = "missing-encryption-wg"

  configuration {
    result_configuration {
      output_location = "s3://ath-001-fixture-bucket/results/"

      encryption_configuration {
        kms_key_arn = "arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
      }
    }
  }
}

## Scenario 2: missing-kms-key
## Uses SSE_KMS encryption option but does not specify a KMS key.
resource "aws_athena_workgroup" "missing_kms_key" {
  name = "missing-kms-key-wg"

  configuration {
    result_configuration {
      output_location = "s3://ath-001-fixture-bucket/results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
      }
    }
  }
}

## Scenario 3: workgroup-configuration-not-enforced
## Valid encryption configuration (SSE_S3, which requires no KMS key), but
## enforce_workgroup_configuration is explicitly disabled, allowing clients to
## override the result settings.
resource "aws_athena_workgroup" "not_enforced" {
  name = "not-enforced-wg"

  configuration {
    enforce_workgroup_configuration = false

    result_configuration {
      output_location = "s3://ath-001-fixture-bucket/results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
