import { RegisteredControl } from '../../../controls/types.js';
import { lambda004Control } from '../lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../lambda-004/lambda-004.adapter.cfn.js';
import { Lambda004TfAdapterFactory } from '../lambda-004/lambda-004.adapter.tf.js';
import { lambda011Control } from '../lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../lambda-011/lambda-011.adapter.cfn.js';
import { Lambda011TfAdapterFactory } from '../lambda-011/lambda-011.adapter.tf.js';
import { lambda012Control } from '../lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../lambda-012/lambda-012.adapter.cfn.js';
import { Lambda012TfAdapterFactory } from '../lambda-012/lambda-012.adapter.tf.js';
import { lambda015Control } from '../lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../lambda-015/lambda-015.adapter.cfn.js';
import { Lambda015TfAdapterFactory } from '../lambda-015/lambda-015.adapter.tf.js';
import { lambda005Control } from '../lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../lambda-005/lambda-005.adapter.cfn.js';
import { Lambda005TfAdapterFactory } from '../lambda-005/lambda-005.adapter.tf.js';

export const lambdaControls: RegisteredControl[] = [
  { control: lambda004Control, cfnAdapter: new Lambda004CfnAdapterFactory(), tfAdapter: new Lambda004TfAdapterFactory() },
  { control: lambda011Control, cfnAdapter: new Lambda011CfnAdapterFactory(), tfAdapter: new Lambda011TfAdapterFactory() },
  { control: lambda012Control, cfnAdapter: new Lambda012CfnAdapterFactory(), tfAdapter: new Lambda012TfAdapterFactory() },
  { control: lambda015Control, cfnAdapter: new Lambda015CfnAdapterFactory(), tfAdapter: new Lambda015TfAdapterFactory() },
  { control: lambda005Control, cfnAdapter: new Lambda005CfnAdapterFactory(), tfAdapter: new Lambda005TfAdapterFactory() },
];
