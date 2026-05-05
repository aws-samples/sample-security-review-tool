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

interface TerraformPlanJson {
  format_version?: string;
  planned_values?: {
    root_module?: TerraformPlanModule;
  };
}

export async function readTerraformPlan(planJsonPath: string): Promise<TerraformResource[]> {
  try {
    const content = await fs.readFile(planJsonPath, 'utf-8');
    const plan: TerraformPlanJson = JSON.parse(content);

    if (!plan.planned_values?.root_module) {
      return [];
    }

    return extractResources(plan.planned_values.root_module);
  } catch (error) {
    SrtLogger.logError('Error reading Terraform plan', error as Error);
    return [];
  }
}

function extractResources(module: TerraformPlanModule): TerraformResource[] {
  const resources: TerraformResource[] = [];

  if (module.resources) {
    for (const entry of module.resources) {
      resources.push({
        type: entry.type,
        name: entry.name,
        address: entry.address,
        values: entry.values || {}
      });
    }
  }

  if (module.child_modules) {
    for (const child of module.child_modules) {
      resources.push(...extractResources(child));
    }
  }

  return resources;
}
