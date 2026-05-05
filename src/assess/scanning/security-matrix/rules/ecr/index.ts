import rule001 from './001-public-registry-access.cf.js';

export const ecrRules = [
  rule001,
];

export {
  rule001 as publicRegistryAccessRule,
};

import tfRule001 from './001-public-registry-access.tf.js';

export const tfEcrRules = [
  tfRule001,
];
