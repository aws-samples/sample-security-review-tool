import * as fs from 'fs/promises';
import { TerraformResource } from './terraform-rule-base.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

interface TerraformPlanModule {
  resources?: TerraformPlanResourceEntry[];
  child_modules?: TerraformPlanModule[];
  address?: string;
}

interface TerraformPlanResourceEntry {
  type: string;
  name: string;
  address: string;
  values: Record<string, any>;
}

interface TerraformConfigModule {
  resources?: TerraformConfigResourceEntry[];
  module_calls?: Record<string, { module?: TerraformConfigModule }>;
}

interface TerraformConfigResourceEntry {
  address: string;
  type: string;
  name: string;
  expressions?: Record<string, any>;
}

interface TerraformPlanJson {
  format_version?: string;
  planned_values?: { root_module?: TerraformPlanModule };
  configuration?: { root_module?: TerraformConfigModule };
}

export async function readTerraformPlan(planJsonPath: string): Promise<TerraformResource[]> {
  return new TerraformPlanReader().read(planJsonPath);
}

// `planned_values` holds resolved literals but omits any value that is unknown at plan time
// (e.g. an attribute referencing another resource that has not been created yet). The plan's
// `configuration` block preserves those as `{ references: [...] }`. To match how CloudFormation
// preprocessing collapses `!Ref X`/`!GetAtt X.Attr` to the logical-ID string `"X"`, we collapse a
// Terraform reference to the target resource's address (`aws_<type>.<name>`). Adapters then do plain
// string equality against `target.address` instead of inspecting a references array.
export class TerraformPlanReader {
  public async read(planJsonPath: string): Promise<TerraformResource[]> {
    try {
      const content = await fs.readFile(planJsonPath, 'utf-8');
      const plan: TerraformPlanJson = JSON.parse(content);

      if (!plan.planned_values?.root_module) return [];

      const expressionsByAddress = this.collectExpressions(plan.configuration?.root_module);
      return this.extractResources(plan.planned_values.root_module, expressionsByAddress);
    } catch (error) {
      SrtLogger.logError('Error reading Terraform plan', error as Error);
      return [];
    }
  }

  private extractResources(module: TerraformPlanModule, expressionsByAddress: Map<string, Record<string, any>>): TerraformResource[] {
    const resources: TerraformResource[] = [];

    for (const entry of module.resources ?? []) {
      const values = entry.values || {};
      const expressions = expressionsByAddress.get(entry.address);
      resources.push({
        type: entry.type,
        name: entry.name,
        address: entry.address,
        values: expressions ? this.mergeReferences(values, expressions) : values
      });
    }

    for (const child of module.child_modules ?? []) {
      resources.push(...this.extractResources(child, expressionsByAddress));
    }

    return resources;
  }

  private collectExpressions(module: TerraformConfigModule | undefined, modulePrefix = ''): Map<string, Record<string, any>> {
    const byAddress = new Map<string, Record<string, any>>();
    this.collectExpressionsInto(module, modulePrefix, byAddress);
    return byAddress;
  }

  // In `configuration`, child-module resources nest under module_calls.<name>.module.resources with
  // module-relative addresses, while `planned_values` uses full `module.<name>....` addresses. We
  // rebuild the full address while walking so the two trees align.
  private collectExpressionsInto(module: TerraformConfigModule | undefined, modulePrefix: string, byAddress: Map<string, Record<string, any>>): void {
    if (!module) return;

    for (const entry of module.resources ?? []) {
      if (entry.expressions) byAddress.set(modulePrefix + entry.address, entry.expressions);
    }

    for (const [name, call] of Object.entries(module.module_calls ?? {})) {
      this.collectExpressionsInto(call.module, `${modulePrefix}module.${name}.`, byAddress);
    }
  }

  private mergeReferences(values: Record<string, any>, expressions: Record<string, any>): Record<string, any> {
    const merged: Record<string, any> = { ...values };
    for (const [key, expression] of Object.entries(expressions)) {
      merged[key] = this.mergeExpression(values[key], expression);
    }
    return merged;
  }

  private mergeExpression(value: any, expression: any): any {
    if (this.isReferenceExpression(expression)) return this.resolveReference(value, expression.references);
    if (Array.isArray(expression)) return this.mergeExpressionArray(value, expression);
    if (this.isNestedBlock(expression)) return this.mergeNestedBlock(value, expression);
    return value;
  }

  private resolveReference(value: any, references: string[]): any {
    if (value != null) return value;
    return this.extractAddress(references) ?? value;
  }

  private extractAddress(references: string[]): string | null {
    if (!references.length) return null;
    const addresses = references.map(ref => ref.split('.').slice(0, 2).join('.'));
    const first = addresses[0];
    return addresses.every(address => address === first) ? first : null;
  }

  private mergeExpressionArray(value: any, expression: any[]): any {
    const valueArray = Array.isArray(value) ? value : [];
    return expression.map((item, index) => this.mergeExpression(valueArray[index], item));
  }

  private mergeNestedBlock(value: any, expression: Record<string, any>): any {
    const base = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    const merged: Record<string, any> = { ...base };
    for (const [key, childExpression] of Object.entries(expression)) {
      merged[key] = this.mergeExpression(base[key], childExpression);
    }
    return merged;
  }

  private isReferenceExpression(expression: any): boolean {
    return !!expression && typeof expression === 'object' && Array.isArray(expression.references);
  }

  private isNestedBlock(expression: any): boolean {
    return !!expression && typeof expression === 'object' && !Array.isArray(expression) && !('constant_value' in expression);
  }
}
