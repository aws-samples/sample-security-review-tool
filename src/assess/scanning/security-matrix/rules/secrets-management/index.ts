import rule001 from './001-use-secrets-manager.js';
import rule003 from './003-kms-encryption.js';
import rule004 from './004-least-privilege-access.js';
import rule005 from './005-secret-versioning.js';
import rule006 from './006-customer-managed-keys.js';

export const secretsManagementRules = [
  rule001,
  rule003,
  rule004,
  rule005,
  rule006,
];

export {
  rule001 as useSecretsManagerRule,
  rule003 as kmsEncryptionRule,
  rule004 as leastPrivilegeAccessRule,
  rule005 as secretVersioningRule,
  rule006 as customerManagedKeysRule,
};
