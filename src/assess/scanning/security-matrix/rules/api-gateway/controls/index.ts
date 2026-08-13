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

export const apiGatewayControls: RegisteredControl[] = [
  { control: apigw001Control, cfnAdapter: new Apigw001CfnAdapterFactory(), tfAdapter: new Apigw001TfAdapterFactory() },
  { control: apigw002Control, cfnAdapter: new Apigw002CfnAdapterFactory(), tfAdapter: new Apigw002TfAdapterFactory() },
  { control: apigw003Control, cfnAdapter: new Apigw003CfnAdapterFactory(), tfAdapter: new Apigw003TfAdapterFactory() },
  { control: apigw004Control, cfnAdapter: new Apigw004CfnAdapterFactory(), tfAdapter: new Apigw004TfAdapterFactory() },
];
