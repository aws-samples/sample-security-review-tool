import rule001 from './001-access-logging.cf.js';
import rule002 from './002-request-validation.cf.js';
import rule003 from './003-waf-protection.cf.js';
import rule004 from './004-authentication.cf.js';
import rule005 from './005-vpc-privatelink.cf.js';
import rule006 from './006-cloudwatch-logs.cf.js';
import rule007 from './007-access-control.cf.js';
import rule008 from './008-cache-encryption.cf.js';
import rule009 from './009-private-endpoints.cf.js';
// rule010 (APIG10 - Sensitive info logging) is not implemented as it's impossible to fully detect automatically because the content of logged parameters depends on runtime API inputs

export const apiGatewayRules = [
  rule001,
  rule002,
  rule003,
  rule004,
  rule005,
  rule006,
  rule007,
  rule008,
  rule009
];

export {
  rule001 as accessLoggingRule,
  rule002 as requestValidationRule,
  rule003 as wafProtectionRule,
  rule004 as authenticationRule,
  rule005 as vpcPrivateLinkRule,
  rule006 as cloudwatchLogsRule,
  rule007 as accessControlRule,
  rule008 as cacheEncryptionRule,
  rule009 as privateEndpointsRule
};

import tfRule001 from './001-access-logging.tf.js';
import tfRule002 from './002-request-validation.tf.js';
import tfRule003 from './003-waf-protection.tf.js';
import tfRule004 from './004-authentication.tf.js';
import tfRule005 from './005-vpc-privatelink.tf.js';
import tfRule006 from './006-cloudwatch-logs.tf.js';
import tfRule007 from './007-access-control.tf.js';
import tfRule008 from './008-cache-encryption.tf.js';
import tfRule009 from './009-private-endpoints.tf.js';

export const tfApiGatewayRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
  tfRule007,
  tfRule008,
  tfRule009,
];
