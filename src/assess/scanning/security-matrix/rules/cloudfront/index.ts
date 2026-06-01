// rule001 (CFR1 - Geo restrictions) is not implemented as determining which geographies should be allowed or blocked requires understanding the business use case, which cannot be inferred automatically
import rule005 from './005-origin-https.cf.js';

export const cloudfrontRules = [
  rule005,
];

export {
  rule005 as originHttpsRule,
};

import tfRule004 from './005-origin-https.tf.js';

export const tfCloudfrontRules = [
  tfRule004,
];
