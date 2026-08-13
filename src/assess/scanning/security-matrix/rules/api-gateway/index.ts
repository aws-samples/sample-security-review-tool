import rule008 from './008-cache-encryption.cf.js';
// rule010 (APIG10 - Sensitive info logging) is not implemented as it's impossible to fully detect automatically because the content of logged parameters depends on runtime API inputs

export const apiGatewayRules = [
  rule008,
];

export {
  rule008 as cacheEncryptionRule,
};

import tfRule008 from './008-cache-encryption.tf.js';

export const tfApiGatewayRules = [
  tfRule008,
];
