import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnWorkGroup } from 'aws-cdk-lib/aws-athena';

/**
 * Fixture stack for ATH-001: Athena workgroups must have query result
 * encryption enabled using SSE_S3, SSE_KMS, or CSE_KMS, with a KMS key
 * specified when SSE_KMS or CSE_KMS is used.
 *
 * Triggers all remediation scenarios:
 *  1. missing-query-result-encryption - no EncryptionConfiguration at all.
 *  2. missing-kms-key - SSE_KMS selected but no KmsKey specified.
 *  3. workgroup-configuration-not-enforced - valid SSE_S3 encryption present,
 *     but EnforceWorkGroupConfiguration explicitly set to false.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Scenario 1: missing-query-result-encryption
    // No ResultConfiguration/EncryptionConfiguration at all.
    new CfnWorkGroup(this, 'MissingEncryptionWorkGroup', {
      name: 'missing-encryption-workgroup',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: 's3://fixture-athena-results/missing-encryption/',
        },
      },
    });

    // Scenario 2: missing-kms-key
    // SSE_KMS encryption option selected, but no KmsKey specified.
    new CfnWorkGroup(this, 'MissingKmsKeyWorkGroup', {
      name: 'missing-kms-key-workgroup',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: 's3://fixture-athena-results/missing-kms-key/',
          encryptionConfiguration: {
            encryptionOption: 'SSE_KMS',
          },
        },
      },
    });

    // Scenario 3: workgroup-configuration-not-enforced
    // Valid SSE_S3 encryption is present (passes encryption checks), but
    // EnforceWorkGroupConfiguration is explicitly false, so clients can
    // override the settings with unencrypted result configurations.
    new CfnWorkGroup(this, 'NotEnforcedWorkGroup', {
      name: 'not-enforced-workgroup',
      workGroupConfiguration: {
        enforceWorkGroupConfiguration: false,
        resultConfiguration: {
          outputLocation: 's3://fixture-athena-results/not-enforced/',
          encryptionConfiguration: {
            encryptionOption: 'SSE_S3',
          },
        },
      },
    });
  }
}
