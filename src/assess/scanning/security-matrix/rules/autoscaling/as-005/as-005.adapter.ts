import { ControlAdapter } from '../../../controls/types.js';

export interface As005Adapter extends ControlAdapter {
  /** True when the group names a launch configuration as an instance configuration source. */
  usesLaunchConfiguration(): boolean;
  /** True when the group declares a direct launch template reference, whatever that reference contains. */
  declaresLaunchTemplateReference(): boolean;
  /** True when the group references a launch template directly. */
  usesLaunchTemplate(): boolean;
  /** True when the group defines a mixed instances policy, whatever that policy contains. */
  hasMixedInstancesPolicy(): boolean;
  /** True when the group's mixed instances policy supplies a launch template of its own. */
  mixedInstancesPolicyUsesLaunchTemplate(): boolean;
  /** True when the group takes its instance configuration from an existing EC2 instance identifier. */
  usesExistingInstance(): boolean;
}
