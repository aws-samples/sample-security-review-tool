import rule006 from './006-cloudwatch-logs.cf.js';
import rule007 from './007-access-control.cf.js';
import rule008 from './008-cache-encryption.cf.js';
import rule009 from './009-private-endpoints.cf.js';
// rule010 (APIG10 - Sensitive info logging) is not implemented as it's impossible to fully detect automatically because the content of logged parameters depends on runtime API inputs

export const apiGatewayRules = [
  rule006,
  rule007,
  rule008,
  rule009
];

export {
  rule006 as cloudwatchLogsRule,
  rule007 as accessControlRule,
  rule008 as cacheEncryptionRule,
  rule009 as privateEndpointsRule
};

import tfRule006 from './006-cloudwatch-logs.tf.js';
import tfRule007 from './007-access-control.tf.js';
import tfRule008 from './008-cache-encryption.tf.js';
import tfRule009 from './009-private-endpoints.tf.js';

export const tfApiGatewayRules = [
  tfRule006,
  tfRule007,
  tfRule008,
  tfRule009,
];
