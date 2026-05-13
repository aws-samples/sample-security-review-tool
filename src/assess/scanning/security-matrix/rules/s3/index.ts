import rule002 from './002-least-privilege-bucket-policy.cf.js';
import rule005 from './005-cloudfront-origin-access-control.cf.js';
import rule008 from './008-lifecycle-policies.cf.js';

export const s3Rules = [
  rule002,
  rule005,
  rule008,
];

import tfRule002 from './002-least-privilege-bucket-policy.tf.js';
import tfRule005 from './005-cloudfront-origin-access-control.tf.js';
import tfRule008 from './008-lifecycle-policies.tf.js';

export const tfS3Rules = [
  tfRule002,
  tfRule005,
  tfRule008,
];

export default tfS3Rules;