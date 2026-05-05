import rule001 from './001-transit-gateway-registration.cf.js';

export const networkManagerRules = [
  rule001
];

export {
  rule001 as transitGatewayRegistrationRule
};

import tfRule001 from './001-transit-gateway-registration.tf.js';

export const tfNetworkManagerRules = [
  tfRule001,
];
