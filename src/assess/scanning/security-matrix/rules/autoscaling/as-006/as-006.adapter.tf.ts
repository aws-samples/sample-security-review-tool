import { AdapterFactory, TerraformResource, TfContext } from '../../../controls/types.js';
import { isUnresolved } from '../../../terraform-rule-base.js';
import { As006Adapter, PlacementCount } from './as-006.adapter.js';

const SUBNET_TYPE = 'aws_subnet';
const ZONE_ARGUMENTS = ['availability_zone', 'availability_zone_id'];
/** A list holding one entry names exactly one zone, whether or not that zone is known. */
const SINGLE_ENTRY = 1;

export class As006TfAdapterFactory implements AdapterFactory<TfContext> {
  readonly applicableResourceTypes = ['aws_autoscaling_group'];

  appliesTo(resourceType: string): boolean {
    return this.applicableResourceTypes.includes(resourceType);
  }

  bind(context: TfContext): As006TfAdapter {
    return new As006TfAdapter(context);
  }
}

class As006TfAdapter implements As006Adapter {
  readonly resourceId: string;
  readonly resourceType: string;

  constructor(private readonly ctx: TfContext) {
    this.resourceId = ctx.resource.address;
    this.resourceType = ctx.resource.type;
  }

  hasAvailabilityZones(): boolean {
    return this.isPresent(this.argument('availability_zones'));
  }

  hasSubnets(): boolean {
    return this.isPresent(this.argument('vpc_zone_identifier'));
  }

  /** Repeated entries name the same zone, so only distinct entries add coverage. */
  availabilityZoneCount(): PlacementCount {
    const zones = this.argument('availability_zones');
    if (this.isSingleEntryList(zones)) return SINGLE_ENTRY;
    return this.mapEntries(zones, entries => new Set(entries).size);
  }

  subnetCount(): PlacementCount {
    return this.mapEntries(this.argument('vpc_zone_identifier'), entries => entries.length);
  }

  subnetZoneCount(): PlacementCount {
    const zones = this.subnetZoneNames();
    return zones === null ? null : new Set(zones).size;
  }

  /** Named zones and subnet zones can name the same zone, so coverage is their union. */
  combinedZoneCount(): PlacementCount {
    const declared = this.entries(this.argument('availability_zones'));
    const subnetZones = this.subnetZoneNames();
    if (declared === null || subnetZones === null) return null;
    return new Set([...declared, ...subnetZones]).size;
  }

  private subnetZoneNames(): string[] | null {
    const references = this.entries(this.argument('vpc_zone_identifier'));
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
    const values = this.findSubnet(reference)?.values as Record<string, unknown> | undefined;
    for (const name of ZONE_ARGUMENTS) {
      const zone = values?.[name];
      if (typeof zone !== 'string' || isUnresolved(zone) || zone.trim().length === 0) continue;
      return zone.trim();
    }
    return null;
  }

  private findSubnet(reference: string): TerraformResource | undefined {
    return this.ctx.allResources?.find(resource =>
      resource.type === SUBNET_TYPE && (resource.address === reference || resource.name === reference));
  }

  private argument(name: string): unknown {
    const values = this.ctx.resource.values as Record<string, unknown> | undefined;
    return values?.[name];
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
    if (typeof value === 'string') return value.trim().length > 0 ? [value.trim()] : [];
    return null;
  }

  private isUnknown(entry: unknown): boolean {
    if (typeof entry === 'string') return isUnresolved(entry);
    return typeof entry === 'object' && entry !== null;
  }

  private isPresent(value: unknown): boolean {
    if (value === undefined || value === null) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'string') return value.trim().length > 0;
    return true;
  }
}
