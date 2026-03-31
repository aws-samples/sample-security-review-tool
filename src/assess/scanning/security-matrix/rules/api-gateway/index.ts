import rule001 from './001-access-logging.js';
import rule002 from './002-request-validation.js';
import rule003 from './003-waf-protection.js';
import rule004 from './004-authentication.js';
import rule005 from './005-vpc-privatelink.js';
import rule006 from './006-cloudwatch-logs.js';
import rule007 from './007-access-control.js';
import rule008 from './008-cache-encryption.js';
import rule009 from './009-private-endpoints.js';
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
