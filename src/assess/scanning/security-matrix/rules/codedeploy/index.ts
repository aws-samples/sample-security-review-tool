import rule001 from './001-cloudwatch-alarms.cf.js';

export const codedeployRules = [
  rule001
];

export {
  rule001 as cloudwatchAlarmsRule
};
import tfRule001 from './001-cloudwatch-alarms.tf.js';

export const tfCodedeployRules = [
  tfRule001,
];
