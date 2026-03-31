import rule001 from './001-s3-artifact-encryption.js';
import rule002 from './002-secrets-manager-usage.js';

export const codepipelineRules = [
  rule001,
  rule002
];

export {
  rule001 as s3ArtifactEncryptionRule,
  rule002 as secretsManagerUsageRule
};