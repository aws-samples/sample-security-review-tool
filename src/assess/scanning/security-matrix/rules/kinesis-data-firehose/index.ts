import KDF001Rule from './001-server-side-encryption.cf.js';
import KDF002Rule from './002-destination-encryption.cf.js';

export const kinesisDataFirehoseRules = [
  KDF001Rule,
  KDF002Rule,
];

export default kinesisDataFirehoseRules;
import tfRule001 from './001-server-side-encryption.tf.js';
import tfRule002 from './002-destination-encryption.tf.js';

export const tfKinesisDataFirehoseRules = [
  tfRule001,
  tfRule002,
];
