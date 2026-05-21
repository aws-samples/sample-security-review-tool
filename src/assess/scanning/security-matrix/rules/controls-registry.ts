import { RegisteredControl } from '../controls/types.js';
import { lambdaControls } from './lambda/controls/index.js';
import { dynamodbControls } from './dynamodb/controls/index.js';
import { s3Controls } from './s3/controls/index.js';

export const allRegisteredControls: RegisteredControl[] = [
  ...s3Controls,
  ...dynamodbControls,
  ...lambdaControls,
];
