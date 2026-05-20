import { RegisteredControl } from '../controls/types.js';
import { lambdaControls } from './lambda/controls/index.js';

export const allRegisteredControls: RegisteredControl[] = [
  ...lambdaControls,
];
