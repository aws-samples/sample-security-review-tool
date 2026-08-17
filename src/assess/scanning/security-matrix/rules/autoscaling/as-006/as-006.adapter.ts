import { ControlAdapter } from '../../../controls/types.js';

/** Count of a placement collection, or null when the configuration cannot be determined. */
export type PlacementCount = number | null;

export interface As006Adapter extends ControlAdapter {
  /** True when the group declares a list of Availability Zones for placement. */
  hasAvailabilityZones(): boolean;
  /** True when the group declares subnets for placement. */
  hasSubnets(): boolean;
  /** Number of declared Availability Zones, or null when unknown. */
  availabilityZoneCount(): PlacementCount;
  /** Number of declared subnets, or null when unknown. */
  subnetCount(): PlacementCount;
  /**
   * Number of distinct Availability Zones occupied by the declared subnets, based on
   * subnet definitions found alongside the group, or null when they cannot be determined.
   */
  subnetZoneCount(): PlacementCount;
  /**
   * Number of distinct Availability Zones covered by the declared zones together with the
   * zones of the declared subnets, or null when they cannot be determined.
   */
  combinedZoneCount(): PlacementCount;
}
