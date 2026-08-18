import { parse } from '@cdktf/hcl2json';
import * as fs from 'fs/promises';
import * as path from 'path';
import { TerraformResource, unresolved } from './terraform-rule-base.js';
import { SrtLogger } from '../../../shared/logging/srt-logger.js';

interface ModuleSource {
  addressPrefix: string;
  directory: string;
  isRootModule: boolean;
}

interface ModuleManifestEntry {
  Key: string;
  Dir: string;
}

const SINGLE_INTERPOLATION = /^\$\{([^${}]+)\}$/;

const JSON_ENCODE_CALL = 'jsonencode(';
const JSON_ENCODED_KEY = '__srt_json_encoded__';

const NON_RESOURCE_NAMESPACES = new Set(['var', 'local', 'module', 'data', 'each', 'count', 'path', 'self', 'terraform']);

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
    const root: ModuleSource = { addressPrefix: '', directory: projectRootPath, isRootModule: true };
    const manifestPath = path.join(projectRootPath, '.terraform', 'modules', 'modules.json');

    const manifest = await fs
      .readFile(manifestPath, 'utf-8')
      .then(text => JSON.parse(text) as { Modules?: ModuleManifestEntry[] })
      .catch(() => null);

    if (!manifest?.Modules) return [root];

    const downloaded = manifest.Modules.filter(entry => entry.Key !== '').map(entry => ({
      addressPrefix: this.addressPrefixFor(entry.Key),
      directory: path.resolve(projectRootPath, entry.Dir),
      isRootModule: false
    }));

    return [root, ...downloaded];
  }

  private addressPrefixFor(key: string): string {
    return `${key.split('.').map(segment => `module.${segment}`).join('.')}.`;
  }

  private async readModule(module: ModuleSource): Promise<TerraformResource[]> {
    const bodies = await this.parseModule(module);
    const shared = module.isRootModule ? this.mergedVariableDefaults(bodies) : null;

    return bodies.flatMap(body => this.extractResources(body, module.addressPrefix, shared ?? this.variableDefaults(body)));
  }

  private async parseModule(module: ModuleSource): Promise<Record<string, any>[]> {
    const files = await fs.readdir(module.directory).catch(() => []);
    const bodies: Record<string, any>[] = [];

    for (const file of files.filter(name => name.endsWith('.tf')).sort()) {
      const body = await this.parseFile(path.join(module.directory, file));
      if (body) bodies.push(body);
    }

    return bodies;
  }

  /**
   * Variables are declared in one file and used in another — `variables.tf` and `main.tf` is the
   * usual split — so the root module's declarations are pooled before any resource is resolved.
   * A downloaded module's variables are its caller's arguments, and the value passed in is not
   * read here, so its declared defaults stay file-scoped rather than standing in for one.
   */
  private mergedVariableDefaults(bodies: Record<string, any>[]): Map<string, unknown> {
    const merged = new Map<string, unknown>();

    for (const body of bodies) {
      for (const [name, value] of this.variableDefaults(body)) merged.set(name, value);
    }

    return merged;
  }

  private async parseFile(filePath: string): Promise<Record<string, any> | null> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const fileName = path.basename(filePath);
      return await parse(fileName, this.exposeJsonEncodedValues(content)).catch(() => parse(fileName, content));
    } catch (error) {
      SrtLogger.logError(`Error parsing Terraform file ${filePath}`, error as Error);
      return null;
    }
  }

  private exposeJsonEncodedValues(text: string): string {
    let index = text.indexOf(JSON_ENCODE_CALL);

    while (index !== -1) {
      const argument = index + JSON_ENCODE_CALL.length;
      const end = this.closingParen(text, argument);
      if (end === -1) return text;

      text = `${text.slice(0, index)}{ ${JSON_ENCODED_KEY} = ${text.slice(argument, end)} }${text.slice(end + 1)}`;
      index = text.indexOf(JSON_ENCODE_CALL, index);
    }

    return text;
  }

  private closingParen(text: string, from: number): number {
    let depth = 1;
    let quoted = false;

    for (let index = from; index < text.length; index++) {
      const character = text[index];
      if (character === '\\') index++;
      else if (character === '"') quoted = !quoted;
      else if (quoted) continue;
      else if (character === '(') depth++;
      else if (character === ')' && --depth === 0) return index;
    }

    return -1;
  }

  private extractResources(body: Record<string, any>, addressPrefix: string, variableDefaults: Map<string, unknown>): TerraformResource[] {
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

  private resolveObject(value: Record<string, unknown>, variableDefaults: Map<string, unknown>): unknown {
    if (JSON_ENCODED_KEY in value) return JSON.stringify(value[JSON_ENCODED_KEY]);

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

    return this.resourceAddress(expression) ?? unresolved(expression);
  }

  private variableDefault(expression: string, variableDefaults: Map<string, unknown>): unknown {
    if (!expression.startsWith('var.')) return undefined;
    return variableDefaults.get(expression.slice('var.'.length));
  }

  private resourceAddress(expression: string): string | null {
    if (!/^[A-Za-z_][A-Za-z0-9_.[\]"-]*$/.test(expression)) return null;

    const segments = expression.split('.');
    if (segments.length < 2) return null;
    if (NON_RESOURCE_NAMESPACES.has(segments[0])) return null;

    return segments.slice(0, 2).join('.');
  }
}
