// rule001 (CFR1 - Geo restrictions) is not implemented as determining which geographies should be allowed or blocked requires understanding the business use case, which cannot be inferred automatically
import rule002 from './002-waf-protection.cf.js';
import rule003 from './003-access-logging.cf.js';
import rule004 from './004-https-only.cf.js';
import rule005 from './005-origin-https.cf.js';
import rule006 from './006-origin-access-control.cf.js';

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

import tfRule001 from './002-waf-protection.tf.js';
import tfRule002 from './003-access-logging.tf.js';
import tfRule003 from './004-https-only.tf.js';
import tfRule004 from './005-origin-https.tf.js';
import tfRule005 from './006-origin-access-control.tf.js';

export const tfCloudfrontRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
  tfRule005,
];
