import MEDIAPACKAGE003 from './003-endpoint-access-control.cf.js';
import MEDIAPACKAGE007 from './007-key-rotation-interval.cf.js';

export { MEDIAPACKAGE003, MEDIAPACKAGE007 };

export const mediapackageRules = [
  MEDIAPACKAGE003,
  MEDIAPACKAGE007,
];
import tfRule001 from './003-endpoint-access-control.tf.js';
import tfRule002 from './007-key-rotation-interval.tf.js';

export const tfMediapackageRules = [
  tfRule001,
  tfRule002,
];
