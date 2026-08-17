export { default as AS003Rule } from './003-email-notifications.cf.js';
export { default as AS004Rule } from './004-load-balancer-integration.cf.js';
export { default as AS005Rule } from './005-iam-roles-launch-templates.cf.js';
export { default as AS006Rule } from './006-multiple-availability-zones.cf.js';
import tfRule003 from './003-email-notifications.tf.js';
import tfRule004 from './004-load-balancer-integration.tf.js';
import tfRule005 from './005-iam-roles-launch-templates.tf.js';
import tfRule006 from './006-multiple-availability-zones.tf.js';

export const tfAutoscalingRules = [
  tfRule003,
  tfRule004,
  tfRule005,
  tfRule006,
];

import { RegisteredControl } from '../../controls/types.js';
import { as001Control } from './as-001/as-001.control.js';
import { As001CfnAdapterFactory } from './as-001/as-001.adapter.cfn.js';
import { As001TfAdapterFactory } from './as-001/as-001.adapter.tf.js';

export const autoscalingControls: RegisteredControl[] = [
  { control: as001Control, cfnAdapter: new As001CfnAdapterFactory(), tfAdapter: new As001TfAdapterFactory() },
];
