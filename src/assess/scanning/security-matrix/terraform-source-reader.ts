import { parse } from '@cdktf/hcl2json';
import * as fs from 'fs/promises';
import * as path from 'path';
import { TerraformResource } from './terraform-rule-base.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

interface ModuleSource {
  addressPrefix: string;
  directory: string;
}

interface ModuleManifestEntry {
  Key: string;
  Dir: string;
}

const SINGLE_INTERPOLATION = /^\$\{([^${}]+)\}$/;

export async function readTerraformSource(projectRootPath: string): Promise<TerraformResource[]> {
  return new TerraformSourceReader().read(projectRootPath);
}

export class TerraformSourceReader {
  public async read(projectRootPath: string): Promise<TerraformResource[]> {
    try {
      const modules = await this.moduleSources(projectRootPath);
      const resources: TerraformResource[] = [];

      for (const module of modules) {
        resources.push(...await this.readModule(module));
      }

      return resources;
    } catch (error) {
      SrtLogger.logError('Error reading Terraform source', error as Error);
      return [];
    }
  }

  private async moduleSources(projectRootPath: string): Promise<ModuleSource[]> {
    const root: ModuleSource = { addressPrefix: '', directory: projectRootPath };
    const manifestPath = path.join(projectRootPath, '.terraform', 'modules', 'modules.json');

    const manifest = await fs
      .readFile(manifestPath, 'utf-8')
      .then(text => JSON.parse(text) as { Modules?: ModuleManifestEntry[] })
      .catch(() => null);

    if (!manifest?.Modules) return [root];

    const downloaded = manifest.Modules.filter(entry => entry.Key !== '').map(entry => ({
      addressPrefix: this.addressPrefixFor(entry.Key),
      directory: path.resolve(projectRootPath, entry.Dir)
    }));

    return [root, ...downloaded];
  }

  private addressPrefixFor(key: string): string {
    return `${key.split('.').map(segment => `module.${segment}`).join('.')}.`;
  }

  private async readModule(module: ModuleSource): Promise<TerraformResource[]> {
    const files = await fs.readdir(module.directory).catch(() => []);
    const resources: TerraformResource[] = [];

    for (const file of files.filter(name => name.endsWith('.tf'))) {
      const filePath = path.join(module.directory, file);
      const body = await this.parseFile(filePath);
      if (body) resources.push(...this.extractResources(body, module.addressPrefix));
    }

    return resources;
  }

  private async parseFile(filePath: string): Promise<Record<string, any> | null> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      return await parse(path.basename(filePath), content);
    } catch (error) {
      SrtLogger.logError(`Error parsing Terraform file ${filePath}`, error as Error);
      return null;
    }
  }

  private extractResources(body: Record<string, any>, addressPrefix: string): TerraformResource[] {
    const variableDefaults = this.variableDefaults(body);
    const resources: TerraformResource[] = [];

    for (const [type, byName] of Object.entries(body.resource ?? {})) {
      for (const [name, bodies] of Object.entries(byName as Record<string, unknown>)) {
        const values = this.mergeBodies(bodies);
        resources.push({
          type,
          name,
          address: `${addressPrefix}${type}.${name}`,
          values: this.resolve(values, variableDefaults) as Record<string, any>
        });
      }
    }

    return resources;
  }

  private mergeBodies(bodies: unknown): Record<string, any> {
    if (!Array.isArray(bodies)) return (bodies ?? {}) as Record<string, any>;
    return Object.assign({}, ...bodies.filter(entry => entry && typeof entry === 'object'));
  }

  private variableDefaults(body: Record<string, any>): Map<string, unknown> {
    const defaults = new Map<string, unknown>();

    for (const [name, declarations] of Object.entries(body.variable ?? {})) {
      const declaration = this.mergeBodies(declarations);
      if ('default' in declaration) defaults.set(name, declaration.default);
    }

    return defaults;
  }

  private resolve(value: unknown, variableDefaults: Map<string, unknown>): unknown {
    if (typeof value === 'string') return this.resolveString(value, variableDefaults);
    if (Array.isArray(value)) return value.map(entry => this.resolve(entry, variableDefaults));
    if (value && typeof value === 'object') return this.resolveObject(value as Record<string, unknown>, variableDefaults);
    return value;
  }

  private resolveObject(value: Record<string, unknown>, variableDefaults: Map<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, this.resolve(entry, variableDefaults)])
    );
  }

  
  private resolveString(value: string, variableDefaults: Map<string, unknown>): unknown {
    const match = SINGLE_INTERPOLATION.exec(value.trim());
    if (!match) return value;

    const expression = match[1].trim();
    const variableDefault = this.variableDefault(expression, variableDefaults);
    if (variableDefault !== undefined) return variableDefault;

    return this.referenceAddress(expression) ?? value;
  }

  private variableDefault(expression: string, variableDefaults: Map<string, unknown>): unknown {
    if (!expression.startsWith('var.')) return undefined;
    return variableDefaults.get(expression.slice('var.'.length));
  }

  private referenceAddress(expression: string): string | null {
    if (!/^[A-Za-z_][A-Za-z0-9_.[\]"-]*$/.test(expression)) return null;

    const segments = expression.split('.');
    if (segments.length < 2) return null;

    return segments.slice(0, 2).join('.');
  }
}
