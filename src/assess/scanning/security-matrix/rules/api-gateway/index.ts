import rule008 from './008-cache-encryption.cf.js';
import rule009 from './009-private-endpoints.cf.js';
// rule010 (APIG10 - Sensitive info logging) is not implemented as it's impossible to fully detect automatically because the content of logged parameters depends on runtime API inputs

export const apiGatewayRules = [
  rule008,
  rule009
];

export {
  rule008 as cacheEncryptionRule,
  rule009 as privateEndpointsRule
};

import tfRule008 from './008-cache-encryption.tf.js';
import tfRule009 from './009-private-endpoints.tf.js';

export const tfApiGatewayRules = [
  tfRule008,
  tfRule009,
];
