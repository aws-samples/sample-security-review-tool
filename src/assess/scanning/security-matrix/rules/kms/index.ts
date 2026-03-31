import KMS002Rule from './002-cmk-least-privilege.js';
import KMS007Rule from './007-monitoring-configuration.js';

export const kmsRules = [
  KMS002Rule,
  KMS007Rule,
];