import { RegisteredControl } from '../../controls/types.js';
import { cf002Control } from './cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from './cf-002/cf-002.adapter.cfn.js';
import { Cf002TfAdapterFactory } from './cf-002/cf-002.adapter.tf.js';
import { cf004Control } from './cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from './cf-004/cf-004.adapter.cfn.js';
import { Cf004TfAdapterFactory } from './cf-004/cf-004.adapter.tf.js';
import { cf001Control } from './cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from './cf-001/cf-001.adapter.cfn.js';
import { Cf001TfAdapterFactory } from './cf-001/cf-001.adapter.tf.js';
import { cf006Control } from './cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from './cf-006/cf-006.adapter.cfn.js';
import { Cf006TfAdapterFactory } from './cf-006/cf-006.adapter.tf.js';
import { cf003Control } from './cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from './cf-003/cf-003.adapter.cfn.js';
import { Cf003TfAdapterFactory } from './cf-003/cf-003.adapter.tf.js';
import { cf005Control } from './cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from './cf-005/cf-005.adapter.cfn.js';
import { Cf005TfAdapterFactory } from './cf-005/cf-005.adapter.tf.js';

export const cloudfrontControls: RegisteredControl[] = [
  { control: cf002Control, cfnAdapter: new Cf002CfnAdapterFactory(), tfAdapter: new Cf002TfAdapterFactory() },
  { control: cf004Control, cfnAdapter: new Cf004CfnAdapterFactory(), tfAdapter: new Cf004TfAdapterFactory() },
  { control: cf001Control, cfnAdapter: new Cf001CfnAdapterFactory(), tfAdapter: new Cf001TfAdapterFactory() },
  { control: cf006Control, cfnAdapter: new Cf006CfnAdapterFactory(), tfAdapter: new Cf006TfAdapterFactory() },
  { control: cf003Control, cfnAdapter: new Cf003CfnAdapterFactory(), tfAdapter: new Cf003TfAdapterFactory() },
  { control: cf005Control, cfnAdapter: new Cf005CfnAdapterFactory(), tfAdapter: new Cf005TfAdapterFactory() },
];
