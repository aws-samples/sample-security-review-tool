import { RegisteredControl } from '../controls/types.js';
import { s3Controls } from './s3/controls/index.js';

export const allRegisteredControls: RegisteredControl[] = [
  ...s3Controls
];
