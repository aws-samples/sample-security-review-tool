import { RegisteredControl } from '../../../controls/types.js';
import { cf002Control } from '../cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from '../cf-002/cf-002.adapter.cfn.js';
import { Cf002TfAdapterFactory } from '../cf-002/cf-002.adapter.tf.js';

export const cloudfrontControls: RegisteredControl[] = [
  { control: cf002Control, cfnAdapter: new Cf002CfnAdapterFactory(), tfAdapter: new Cf002TfAdapterFactory() },
];
