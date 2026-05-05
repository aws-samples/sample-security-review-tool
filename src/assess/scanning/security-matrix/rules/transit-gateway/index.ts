import rule001 from './001-route-table-isolation.cf.js';

export const transitGatewayRules = [
  rule001
];

export {
  rule001 as routeTableIsolationRule
};

import tfRule001 from './001-route-table-isolation.tf.js';

export const tfTransitGatewayRules = [
  tfRule001,
];
