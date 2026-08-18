import { ControlAdapter } from '../../../controls/types.js';

export interface As004Adapter extends ControlAdapter {
  /** True when the group is attached to a load balancer or target group. */
  isAttachedToLoadBalancer(): boolean;
  /** True when health checks rely on instance status only. */
  usesInstanceStatusHealthChecksOnly(): boolean;
}
