import rule002 from './002-least-privilege-bucket-policy.cf.js';

export const s3Rules = [
  rule002,
];

import tfRule002 from './002-least-privilege-bucket-policy.tf.js';

export const tfS3Rules = [
  tfRule002,
];

export default tfS3Rules;