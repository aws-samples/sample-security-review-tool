import { AdapterFactory, CfnContext, Resource } from '../../../controls/types.js';
import { As006Adapter, PlacementCount } from './as-006.adapter.js';

const SUBNET_TYPE = 'AWS::EC2::Subnet';
const ZONE_PROPERTIES = ['AvailabilityZone', 'AvailabilityZoneId'];
/** Placeholder left by preprocessing for a value only supplied at deployment time. */
const DEPLOY_TIME_PLACEHOLDER = 'DEFAULT';
/** A list holding one entry names exactly one zone, whether or not that zone is known. */
const SINGLE_ENTRY = 1;

export class As006CfnAdapterFactory implements AdapterFactory<CfnContext> {
  readonly applicableResourceTypes = ['AWS::AutoScaling::AutoScalingGroup'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: CfnContext): As006CfnAdapter {
    return new As006CfnAdapter(context);
  }
}

class As006CfnAdapter implements As006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: CfnContext) {
    this.resourceId = ctx.logicalId;
    this.resourceType = ctx.resource.Type;
  }

  hasAvailabilityZones(): boolean {
    return this.isPresent(this.property('AvailabilityZones'));
  }

  hasSubnets(): boolean {
    return this.isPresent(this.property('VPCZoneIdentifier'));
  }

  /** Repeated entries name the same zone, so only distinct entries add coverage. */
  availabilityZoneCount(): PlacementCount {
    const zones = this.property('AvailabilityZones');
    if (this.isSingleEntryList(zones)) return SINGLE_ENTRY;
    return this.countDistinct(zones);
  }

  subnetCount(): PlacementCount {
    return this.count(this.property('VPCZoneIdentifier'));
  }

  subnetZoneCount(): PlacementCount {
    const zones = this.subnetZoneNames();
    return zones === null ? null : new Set(zones).size;
  }

  /** Named zones and subnet zones can name the same zone, so coverage is their union. */
  combinedZoneCount(): PlacementCount {
    const declared = this.entries(this.property('AvailabilityZones'));
    const subnetZones = this.subnetZoneNames();
    if (declared === null || subnetZones === null) return null;
    return new Set([...declared, ...subnetZones]).size;
  }

  private subnetZoneNames(): string[] | null {
    const references = this.entries(this.property('VPCZoneIdentifier'));
    if (references === null) return null;
    const zones: string[] = [];
    for (const reference of references) {
      const zone = this.subnetZone(reference);
      if (zone === null) return null;
      zones.push(zone);
    }
    return zones;
  }

  /** A subnet's single zone may be named or identified; either pins it to one zone. */
  private subnetZone(reference: string): string | null {
    const properties = this.findSubnet(reference)?.Properties as Record<string, unknown> | undefined;
    for (const name of ZONE_PROPERTIES) {
      const zone = properties?.[name];
      if (typeof zone !== 'string') continue;
      const trimmed = zone.trim();
      if (trimmed.length === 0 || this.isDeployTimeValue(trimmed)) continue;
      return trimmed;
    }
    return null;
  }

  private findSubnet(logicalId: string): Resource | undefined {
    const resources = this.ctx.template.Resources as Record<string, Resource> | undefined;
    const resource = resources?.[logicalId];
    return resource?.Type === SUBNET_TYPE ? resource : undefined;
  }

  private property(name: string): unknown {
    const properties = this.ctx.resource.Properties as Record<string, unknown> | undefined;
    return properties?.[name];
  }

  private count(value: unknown): PlacementCount {
    return this.mapEntries(value, entries => entries.length);
  }

  private countDistinct(value: unknown): PlacementCount {
    return this.mapEntries(value, entries => new Set(entries).size);
  }

  private mapEntries(value: unknown, tally: (entries: string[]) => number): PlacementCount {
    const entries = this.entries(value);
    return entries === null ? null : tally(entries);
  }

  /**
   * True when the list itself is written out and holds exactly one entry: the entry names one
   * zone even when its value only arrives at deployment time. A list supplied wholesale by a
   * deployment-time input is not such a list, because its length is unknown.
   */
  private isSingleEntryList(value: unknown): boolean {
    if (!Array.isArray(value)) return false;
    return value.filter(entry => this.isPresent(entry)).length === SINGLE_ENTRY;
  }

  private entries(value: unknown): string[] | null {
    const declared = this.declaredEntries(value);
    if (declared === null) return null;
    if (declared.some(entry => this.isUnknown(entry))) return null;
    return declared.map(entry => String(entry).trim());
  }

  /** Entries as written, retaining those whose value is only known at deployment time. */
  private declaredEntries(value: unknown): unknown[] | null {
    if (value === undefined || value === null) return [];
    if (Array.isArray(value)) return value.filter(entry => this.isPresent(entry));
    if (typeof value === 'string') return this.splitCommaSeparated(value);
    return null;
  }

  private splitCommaSeparated(value: string): string[] {
    return value.split(',').map(part => part.trim()).filter(part => part.length > 0);
  }

  private isUnknown(entry: unknown): boolean {
    if (typeof entry === 'string') return this.isDeployTimeValue(entry.trim());
    return typeof entry === 'object' && entry !== null;
  }

  private isDeployTimeValue(value: string): boolean {
    return value === DEPLOY_TIME_PLACEHOLDER;
  }

  private isPresent(value: unknown): boolean {
    if (value === undefined || value === null) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'string') return value.trim().length > 0;
    return true;
  }
}
