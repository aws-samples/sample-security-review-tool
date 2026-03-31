// rule001 (CFR1 - Geo restrictions) is not implemented as determining which geographies should be allowed or blocked requires understanding the business use case, which cannot be inferred automatically
import rule002 from './002-waf-protection.js';
import rule003 from './003-access-logging.js';
import rule004 from './004-https-only.js';
import rule005 from './005-origin-https.js';
import rule006 from './006-origin-access-control.js';

export const cloudfrontRules = [
  rule002,
  rule003,
  rule004,
  rule005,
  rule006,
];

export {
  rule002 as wafProtectionRule,
  rule003 as accessLoggingRule,
  rule004 as httpsOnlyRule,
  rule005 as originHttpsRule,
  rule006 as originAccessControlRule,
};
