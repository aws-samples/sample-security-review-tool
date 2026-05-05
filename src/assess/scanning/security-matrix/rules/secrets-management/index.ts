import rule001 from './001-use-secrets-manager.cf.js';
import rule003 from './003-kms-encryption.cf.js';
import rule004 from './004-least-privilege-access.cf.js';
import rule005 from './005-secret-versioning.cf.js';
import rule006 from './006-customer-managed-keys.cf.js';

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

import tfRule001 from './001-use-secrets-manager.tf.js';
import tfRule002 from './003-kms-encryption.tf.js';
import tfRule003 from './004-least-privilege-access.tf.js';
import tfRule004 from './005-secret-versioning.tf.js';
import tfRule005 from './006-customer-managed-keys.tf.js';

export const tfSecretsManagementRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
];
