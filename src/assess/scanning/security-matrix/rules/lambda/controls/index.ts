import { RegisteredControl } from '../../../controls/types.js';
import { lambda004Control } from '../lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../lambda-004/lambda-004.adapter.cfn.js';
import { Lambda004TfAdapterFactory } from '../lambda-004/lambda-004.adapter.tf.js';
import { lambda011Control } from '../lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../lambda-011/lambda-011.adapter.cfn.js';
import { Lambda011TfAdapterFactory } from '../lambda-011/lambda-011.adapter.tf.js';

export const lambdaControls: RegisteredControl[] = [
  { control: lambda004Control, cfnAdapter: new Lambda004CfnAdapterFactory(), tfAdapter: new Lambda004TfAdapterFactory() },
  { control: lambda011Control, cfnAdapter: new Lambda011CfnAdapterFactory(), tfAdapter: new Lambda011TfAdapterFactory() },
];
