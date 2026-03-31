import KDF001Rule from './001-server-side-encryption.js';
import KDF002Rule from './002-destination-encryption.js';

export const kinesisDataFirehoseRules = [
  KDF001Rule,
  KDF002Rule,
];

export default kinesisDataFirehoseRules;