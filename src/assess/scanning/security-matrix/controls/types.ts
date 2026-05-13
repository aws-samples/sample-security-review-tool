import { Template } from 'cloudform-types';
import { TerraformResource } from '../terraform-rule-base.js';
import { ScanResult } from '../../types.js';

type Resource = NonNullable<Template['Resources']>[string];
export type { Resource, Template, TerraformResource, ScanResult };

export interface CfnContext {
  readonly stackName: string;
  readonly template: Template;
  readonly resource: Resource;
  readonly logicalId: string;
}

export interface TfContext {
  readonly projectName: string;
  readonly resource: TerraformResource;
  readonly allResources: TerraformResource[];
}

export type IacContext = CfnContext | TfContext;

export type Priority = 'HIGH' | 'MEDIUM' | 'LOW';

export interface RemediationScenario {
  readonly scenario: string;
  readonly intent: string;
}

export interface IacRemediation {
  readonly scenario: string;
  readonly guidance: string;
}

export interface ControlFinding {
  readonly scenario: string;
  readonly issue?: string;
}

export interface BoundAdapter {
  readonly resourceId: string;
  readonly resourceType: string;
  getRemediation(scenario: string): IacRemediation | null;
}

export interface AdapterFactory<TContext extends IacContext> {
  readonly applicableResourceTypes: string[];
  appliesTo(resourceType: string): boolean;
  bind(context: TContext): BoundAdapter;
}

export interface RegisteredControl {
  readonly control: { readonly id: string; run(adapter: BoundAdapter, context: IacContext): ScanResult | null };
  readonly cfnAdapter: AdapterFactory<CfnContext>;
  readonly tfAdapter: AdapterFactory<TfContext>;
}
