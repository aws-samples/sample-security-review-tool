export { default as AS003Rule } from './003-email-notifications.cf.js';
export { default as AS004Rule } from './004-load-balancer-integration.cf.js';
export { default as AS005Rule } from './005-iam-roles-launch-templates.cf.js';
import tfRule003 from './003-email-notifications.tf.js';
import tfRule004 from './004-load-balancer-integration.tf.js';
import tfRule005 from './005-iam-roles-launch-templates.tf.js';
import { as006Control } from './as-006/as-006.control.js';
import { As006CfnAdapterFactory } from './as-006/as-006.adapter.cfn.js';
import { As006TfAdapterFactory } from './as-006/as-006.adapter.tf.js';

export const tfAutoscalingRules = [
  tfRule003,
  tfRule004,
  tfRule005,
];

import { RegisteredControl } from '../../controls/types.js';
import { as001Control } from './as-001/as-001.control.js';
import { As001CfnAdapterFactory } from './as-001/as-001.adapter.cfn.js';
import { As001TfAdapterFactory } from './as-001/as-001.adapter.tf.js';

export const autoscalingControls: RegisteredControl[] = [
  { control: as001Control, cfnAdapter: new As001CfnAdapterFactory(), tfAdapter: new As001TfAdapterFactory() },
  { control: as006Control, cfnAdapter: new As006CfnAdapterFactory(), tfAdapter: new As006TfAdapterFactory() },
];
