// rule001 (CFR1 - Geo restrictions) is not implemented as determining which geographies should be allowed or blocked requires understanding the business use case, which cannot be inferred automatically
import rule004 from './004-https-only.cf.js';
import rule005 from './005-origin-https.cf.js';

export const cloudfrontRules = [
  rule004,
  rule005,
];

export {
  rule004 as httpsOnlyRule,
  rule005 as originHttpsRule,
};

import tfRule003 from './004-https-only.tf.js';
import tfRule004 from './005-origin-https.tf.js';

export const tfCloudfrontRules = [
  tfRule003,
  tfRule004,
];
