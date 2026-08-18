import { RegisteredControl } from '../controls/types.js';
import { lambdaControls } from './lambda/index.js';
import { dynamodbControls } from './dynamodb/index.js';
import { s3Controls } from './s3/index.js';
import { cloudfrontControls } from './cloudfront/index.js';
import { apiGatewayControls } from './api-gateway/index.js';
import { lexControls } from './lex/index.js';
import { athenaControls } from './athena/index.js';
import { autoscalingControls } from './autoscaling/index.js';
import { codedeployControls } from './codedeploy/index.js';

export const allRegisteredControls: RegisteredControl[] = [
  ...codedeployControls,
  ...autoscalingControls,
  ...athenaControls,
  ...lexControls,
  ...apiGatewayControls,
  ...cloudfrontControls,
  ...s3Controls,
  ...dynamodbControls,
  ...lambdaControls,
];
