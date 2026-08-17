import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { As006Adapter } from './as-006.adapter.js';
import { externalCheck } from '../../../../remediation/external-check.js';

const NO_PLACEMENT_SCENARIO = 'no-placement-specified';
const SINGLE_ZONE_SCENARIO = 'single-availability-zone';
const SINGLE_SUBNET_SCENARIO = 'single-subnet';
const SHARED_SUBNET_ZONE_SCENARIO = 'subnets-in-single-availability-zone';
const SHARED_COMBINED_ZONE_SCENARIO = 'placement-in-single-availability-zone';
const MISMATCHED_SUBNET_ZONE_SCENARIO = 'subnet-outside-declared-availability-zones';
const MULTI_ZONE_THRESHOLD = 2;

export class As006Control extends SecurityControl<As006Adapter> {
  constructor() {
    super({
      id: 'AS-006',
      priority: 'HIGH',
      description: 'Auto Scaling groups must span at least two Availability Zones, either by specifying two or more availability zones or by using two or more subnets (via VPC zone identifier) located in different Availability Zones.',
      remediationScenarios: [
        {
          scenario: NO_PLACEMENT_SCENARIO,
          intent: 'Declare instance placement for the Auto Scaling group so that it covers at least two Availability Zones, either by listing two or more Availability Zones or by referencing two or more subnets that reside in different Availability Zones.',
        },
        {
          scenario: SINGLE_ZONE_SCENARIO,
          intent: 'Broaden the Auto Scaling group placement beyond its single Availability Zone by listing at least one additional Availability Zone, or by referencing two or more subnets that reside in different Availability Zones.',
        },
        {
          scenario: SINGLE_SUBNET_SCENARIO,
          intent: 'Reference at least one additional subnet that resides in a different Availability Zone from the Auto Scaling group\'s current subnet, or list two or more Availability Zones, so that the group spans two or more Availability Zones.',
        },
        {
          scenario: SHARED_SUBNET_ZONE_SCENARIO,
          intent: 'Replace or add a subnet reference on the Auto Scaling group so that its subnets reside in at least two different Availability Zones, or list two or more Availability Zones, so that the group spans two or more Availability Zones.',
        },
        {
          scenario: SHARED_COMBINED_ZONE_SCENARIO,
          intent: 'Extend the Auto Scaling group placement so that its listed Availability Zones and the Availability Zones of its referenced subnets together cover at least two different Availability Zones.',
        },
        {
          scenario: MISMATCHED_SUBNET_ZONE_SCENARIO,
          intent: 'Align the Auto Scaling group placement so that every referenced subnet resides in one of the group\'s listed Availability Zones, and extend that placement so the listed Availability Zones and the matching subnets cover at least two different Availability Zones.',
        },
      ],
      relatedRules: [externalCheck('CKV_AWS_79')],
    });
  }

  protected evaluate(adapter: As006Adapter): ControlFinding | null {
    const zones = adapter.availabilityZoneCount();
    const subnets = adapter.subnetCount();
    if (zones === null || subnets === null) return null;
    if (zones === 0 && subnets === 0) return this.noPlacementFinding();
    if (zones === 0 && subnets === 1) return this.singleSubnetFinding();
    if (zones === 0) return this.evaluateSubnetZones(adapter);
    if (subnets === 0) return zones >= MULTI_ZONE_THRESHOLD ? null : this.singleZoneFinding();
    return this.evaluateCombinedZones(adapter, zones);
  }

  private evaluateSubnetZones(adapter: As006Adapter): ControlFinding | null {
    const zoneCount = adapter.subnetZoneCount();
    if (zoneCount === null) return null;
    if (zoneCount === 1) return this.sharedSubnetZoneFinding();
    return null;
  }

  /**
   * Subnets must reside in the group's listed Availability Zones, so a subnet outside them
   * cannot add usable capacity: each dimension has to reach two zones on its own.
   */
  private evaluateCombinedZones(adapter: As006Adapter, declaredZones: number): ControlFinding | null {
    const subnetZones = adapter.subnetZoneCount();
    if (subnetZones === null) return null;
    if (declaredZones >= MULTI_ZONE_THRESHOLD || subnetZones >= MULTI_ZONE_THRESHOLD) return null;
    const combined = adapter.combinedZoneCount();
    if (combined === null) return null;
    return combined === 1 ? this.sharedCombinedZoneFinding() : this.mismatchedSubnetZoneFinding();
  }

  private noPlacementFinding(): ControlFinding {
    return {
      scenario: NO_PLACEMENT_SCENARIO,
      issue: 'Auto Scaling group declares no Availability Zones and no subnets for instance placement, so it is not spread across two or more Availability Zones',
    };
  }

  private singleZoneFinding(): ControlFinding {
    return {
      scenario: SINGLE_ZONE_SCENARIO,
      issue: 'Auto Scaling group declares a single Availability Zone and no subnets, so all of its instances launch in one Availability Zone',
    };
  }

  private singleSubnetFinding(): ControlFinding {
    return {
      scenario: SINGLE_SUBNET_SCENARIO,
      issue: 'Auto Scaling group declares no Availability Zones and only one subnet, and a single subnet resides in one Availability Zone, so all of its instances launch in one Availability Zone',
    };
  }

  private sharedSubnetZoneFinding(): ControlFinding {
    return {
      scenario: SHARED_SUBNET_ZONE_SCENARIO,
      issue: 'Auto Scaling group declares no Availability Zones and all of its subnets reside in the same Availability Zone, so all of its instances launch in one Availability Zone',
    };
  }

  private sharedCombinedZoneFinding(): ControlFinding {
    return {
      scenario: SHARED_COMBINED_ZONE_SCENARIO,
      issue: 'Auto Scaling group\'s declared Availability Zones and the Availability Zones of its subnets together cover only one Availability Zone, so all of its instances launch in one Availability Zone',
    };
  }

  private mismatchedSubnetZoneFinding(): ControlFinding {
    return {
      scenario: MISMATCHED_SUBNET_ZONE_SCENARIO,
      issue: 'Auto Scaling group declares a single Availability Zone while its subnets reside in a different Availability Zone, so neither its declared Availability Zones nor its subnets provide capacity in two or more Availability Zones',
    };
  }
}

export const as006Control = new As006Control();
