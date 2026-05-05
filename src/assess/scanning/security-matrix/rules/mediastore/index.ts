import MEDIASTORE008 from './008-cors-policy.cf.js';
import MEDIASTORE010 from './010-lifecycle-policy.cf.js';
import MEDIASTORE013 from './013-cloudfront-access.cf.js';
import MEDIASTORE014 from './014-deny-by-default.cf.js';

export { MEDIASTORE008, MEDIASTORE010, MEDIASTORE013, MEDIASTORE014 };

export const mediastoreRules = [
  MEDIASTORE008,
  MEDIASTORE010,
  MEDIASTORE013,
  MEDIASTORE014,
];
import tfRule001 from './008-cors-policy.tf.js';
import tfRule002 from './010-lifecycle-policy.tf.js';
import tfRule003 from './013-cloudfront-access.tf.js';
import tfRule004 from './014-deny-by-default.tf.js';

export const tfMediastoreRules = [
  tfRule001,
  tfRule002,
  tfRule003,
  tfRule004,
];
