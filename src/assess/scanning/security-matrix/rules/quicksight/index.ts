import QS001Rule from './001-tls-database-connection.cf.js';
import QS002Rule from './002-spice-encryption-transit.cf.js';

export const quicksightRules = [
  QS001Rule,
  QS002Rule,
];

export default quicksightRules;
import tfRule001 from './001-tls-database-connection.tf.js';
import tfRule002 from './002-spice-encryption-transit.tf.js';

export const tfQuicksightRules = [
  tfRule001,
  tfRule002,
];
