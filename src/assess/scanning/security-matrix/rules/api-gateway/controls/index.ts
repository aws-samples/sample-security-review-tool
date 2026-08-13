import { RegisteredControl } from '../../../controls/types.js';
import { apigw001Control } from '../apigw-001/apigw-001.control.js';
import { Apigw001CfnAdapterFactory } from '../apigw-001/apigw-001.adapter.cfn.js';
import { Apigw001TfAdapterFactory } from '../apigw-001/apigw-001.adapter.tf.js';
import { apigw002Control } from '../apigw-002/apigw-002.control.js';
import { Apigw002CfnAdapterFactory } from '../apigw-002/apigw-002.adapter.cfn.js';
import { Apigw002TfAdapterFactory } from '../apigw-002/apigw-002.adapter.tf.js';
import { apigw003Control } from '../apigw-003/apigw-003.control.js';
import { Apigw003CfnAdapterFactory } from '../apigw-003/apigw-003.adapter.cfn.js';
import { Apigw003TfAdapterFactory } from '../apigw-003/apigw-003.adapter.tf.js';
import { apigw004Control } from '../apigw-004/apigw-004.control.js';
import { Apigw004CfnAdapterFactory } from '../apigw-004/apigw-004.adapter.cfn.js';
import { Apigw004TfAdapterFactory } from '../apigw-004/apigw-004.adapter.tf.js';
import { apigw005Control } from '../apigw-005/apigw-005.control.js';
import { Apigw005CfnAdapterFactory } from '../apigw-005/apigw-005.adapter.cfn.js';
import { Apigw005TfAdapterFactory } from '../apigw-005/apigw-005.adapter.tf.js';
import { apigw006Control } from '../apigw-006/apigw-006.control.js';
import { Apigw006CfnAdapterFactory } from '../apigw-006/apigw-006.adapter.cfn.js';
import { Apigw006TfAdapterFactory } from '../apigw-006/apigw-006.adapter.tf.js';
import { apigw008Control } from '../apigw-008/apigw-008.control.js';
import { Apigw008CfnAdapterFactory } from '../apigw-008/apigw-008.adapter.cfn.js';
import { Apigw008TfAdapterFactory } from '../apigw-008/apigw-008.adapter.tf.js';

// APIG10 (sensitive info logging) is deliberately absent: what a logged parameter contains
// depends on runtime API inputs, so it cannot be detected from a template.
export const apiGatewayControls: RegisteredControl[] = [
  { control: apigw001Control, cfnAdapter: new Apigw001CfnAdapterFactory(), tfAdapter: new Apigw001TfAdapterFactory() },
  { control: apigw002Control, cfnAdapter: new Apigw002CfnAdapterFactory(), tfAdapter: new Apigw002TfAdapterFactory() },
  { control: apigw003Control, cfnAdapter: new Apigw003CfnAdapterFactory(), tfAdapter: new Apigw003TfAdapterFactory() },
  { control: apigw004Control, cfnAdapter: new Apigw004CfnAdapterFactory(), tfAdapter: new Apigw004TfAdapterFactory() },
  { control: apigw005Control, cfnAdapter: new Apigw005CfnAdapterFactory(), tfAdapter: new Apigw005TfAdapterFactory() },
  { control: apigw006Control, cfnAdapter: new Apigw006CfnAdapterFactory(), tfAdapter: new Apigw006TfAdapterFactory() },
  { control: apigw008Control, cfnAdapter: new Apigw008CfnAdapterFactory(), tfAdapter: new Apigw008TfAdapterFactory() },
];
