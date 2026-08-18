import { as003Control } from './as-003/as-003.control.js';
import { As003CfnAdapterFactory } from './as-003/as-003.adapter.cfn.js';
import { As003TfAdapterFactory } from './as-003/as-003.adapter.tf.js';
import { as006Control } from './as-006/as-006.control.js';
import { As006CfnAdapterFactory } from './as-006/as-006.adapter.cfn.js';
import { As006TfAdapterFactory } from './as-006/as-006.adapter.tf.js';
import { as004Control } from './as-004/as-004.control.js';
import { As004CfnAdapterFactory } from './as-004/as-004.adapter.cfn.js';
import { As004TfAdapterFactory } from './as-004/as-004.adapter.tf.js';
import { as005Control } from './as-005/as-005.control.js';
import { As005CfnAdapterFactory } from './as-005/as-005.adapter.cfn.js';
import { As005TfAdapterFactory } from './as-005/as-005.adapter.tf.js';

// Every autoscaling rule is now a control; the legacy Terraform list stays so
// rules/index.ts keeps a stable import while other services are converted.
export const tfAutoscalingRules = [];

import { RegisteredControl } from '../../controls/types.js';
import { as001Control } from './as-001/as-001.control.js';
import { As001CfnAdapterFactory } from './as-001/as-001.adapter.cfn.js';
import { As001TfAdapterFactory } from './as-001/as-001.adapter.tf.js';

export const autoscalingControls: RegisteredControl[] = [
  { control: as001Control, cfnAdapter: new As001CfnAdapterFactory(), tfAdapter: new As001TfAdapterFactory() },
  { control: as003Control, cfnAdapter: new As003CfnAdapterFactory(), tfAdapter: new As003TfAdapterFactory() },
  { control: as004Control, cfnAdapter: new As004CfnAdapterFactory(), tfAdapter: new As004TfAdapterFactory() },
  { control: as005Control, cfnAdapter: new As005CfnAdapterFactory(), tfAdapter: new As005TfAdapterFactory() },
  { control: as006Control, cfnAdapter: new As006CfnAdapterFactory(), tfAdapter: new As006TfAdapterFactory() },
];
