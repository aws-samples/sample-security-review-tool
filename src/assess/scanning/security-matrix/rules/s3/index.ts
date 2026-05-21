import rule002 from './002-least-privilege-bucket-policy.cf.js';
import rule005 from './005-cloudfront-origin-access-control.cf.js';

export const s3Rules = [
  rule002,
  rule005,
];

import tfRule002 from './002-least-privilege-bucket-policy.tf.js';
import tfRule005 from './005-cloudfront-origin-access-control.tf.js';

export const tfS3Rules = [
  tfRule002,
  tfRule005,
];

export default tfS3Rules;