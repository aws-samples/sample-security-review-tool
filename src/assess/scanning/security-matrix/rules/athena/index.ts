import ATH001Rule from './001-query-results-encryption.cf.js';
import ATH002Rule from './002-encryption-in-transit.cf.js';

export const athenaRules = [
  ATH001Rule,
  ATH002Rule,
];

import tfRule001 from './001-query-results-encryption.tf.js';
import tfRule002 from './002-encryption-in-transit.tf.js';

export const tfAthenaRules = [
  tfRule001,
  tfRule002,
];
