import { RegisteredControl } from '../../../controls/types.js';
import { cf002Control } from '../cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from '../cf-002/cf-002.adapter.cfn.js';
import { Cf002TfAdapterFactory } from '../cf-002/cf-002.adapter.tf.js';
import { cf004Control } from '../cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../cf-004/cf-004.adapter.cfn.js';
import { Cf004TfAdapterFactory } from '../cf-004/cf-004.adapter.tf.js';
import { cf001Control } from '../cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../cf-001/cf-001.adapter.cfn.js';
import { Cf001TfAdapterFactory } from '../cf-001/cf-001.adapter.tf.js';

export const cloudfrontControls: RegisteredControl[] = [
  { control: cf002Control, cfnAdapter: new Cf002CfnAdapterFactory(), tfAdapter: new Cf002TfAdapterFactory() },
  { control: cf004Control, cfnAdapter: new Cf004CfnAdapterFactory(), tfAdapter: new Cf004TfAdapterFactory() },
  { control: cf001Control, cfnAdapter: new Cf001CfnAdapterFactory(), tfAdapter: new Cf001TfAdapterFactory() },
];
