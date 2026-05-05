import rule001 from './001-s3-artifact-encryption.cf.js';
import rule002 from './002-secrets-manager-usage.cf.js';

export const codepipelineRules = [
  rule001,
  rule002
];

export {
  rule001 as s3ArtifactEncryptionRule,
  rule002 as secretsManagerUsageRule
};
import tfRule001 from './001-s3-artifact-encryption.tf.js';
import tfRule002 from './002-secrets-manager-usage.tf.js';

export const tfCodepipelineRules = [
  tfRule001,
  tfRule002,
];
