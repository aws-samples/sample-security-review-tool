import MEDIASTORE008 from './008-cors-policy.js';
import MEDIASTORE010 from './010-lifecycle-policy.js';
import MEDIASTORE013 from './013-cloudfront-access.js';
import MEDIASTORE014 from './014-deny-by-default.js';

export { MEDIASTORE008, MEDIASTORE010, MEDIASTORE013, MEDIASTORE014 };

export const mediastoreRules = [
  MEDIASTORE008,
  MEDIASTORE010,
  MEDIASTORE013,
  MEDIASTORE014,
];