import { RegisteredControl } from '../controls/types.js';
import { lambdaControls } from './lambda/controls/index.js';
import { dynamodbControls } from './dynamodb/index.js';
import { s3Controls } from './s3/index.js';
import { cloudfrontControls } from './cloudfront/index.js';
import { apiGatewayControls } from './api-gateway/controls/index.js';
import { lexControls } from './lex/controls/index.js';
import { athenaControls } from './athena/controls/index.js';

export const allRegisteredControls: RegisteredControl[] = [
  ...athenaControls,
  ...lexControls,
  ...apiGatewayControls,
  ...cloudfrontControls,
  ...s3Controls,
  ...dynamodbControls,
  ...lambdaControls,
];
