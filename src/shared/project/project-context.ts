import * as fs from 'fs/promises';
import { existsSync, statSync } from 'fs';
import * as path from 'path';
import { SrtLogger } from '../logging/srt-logger.js';
import { CfnTemplateValidator } from '../cdk/cfn-template-validator.js';
import { glob } from 'glob';
import { CdkCommandParser } from '../cdk/cdk-command-parser.js';
import { CdkProjectConfig } from '../cdk/types.js';
import { IgnorePatternService } from '../file-system/ignore-pattern-service.js';
import { TerraformDetector } from '../terraform/terraform-detector.js';
import { TerraformProjectConfig } from '../terraform/types.js';

export interface CloudFormationTemplateConfig {
  cfnTemplateName: string;
  cfnTemplateFilePath: string;
  cfnTemplateOutputFolderPath: string;
  cdkProjectName?: string;
}

export interface PythonVenvConfig {
  venvDir: string;
  binDir: string;
  pythonPath: string;
}

export class ProjectContext {
  private readonly cdkCommandParser = new CdkCommandParser();
  private readonly cfnValidator = new CfnTemplateValidator();
  private readonly cdkOutOverridePaths: string[];
  private readonly ignorePatternService: IgnorePatternService;
  private projectRootFolderPath: string;

  constructor(projectRootFolderPath: string, ignorePatternService: IgnorePatternService, cdkOutPaths?: string[]) {
    this.projectRootFolderPath = this.normalizePath(projectRootFolderPath);

    if (!existsSync(this.projectRootFolderPath)) {
      throw new Error(`Project root folder path does not exist: ${this.projectRootFolderPath}`);
    }

    this.ignorePatternService = ignorePatternService;
    this.cdkOutOverridePaths = this.validateCdkOutPaths(cdkOutPaths ?? []);
  }

  public getIgnoredDirectoryNames(): string[] {
    return this.ignorePatternService.getDirectoryNames();
  }

  public getFolderIgnorePatterns(): string[] {
    return this.ignorePatternService.getGlobPatterns();
  }

  public hasCdkOutOverrides(): boolean {
    return this.cdkOutOverridePaths.length > 0;
  }

  public getCdkOutOverridePaths(): string[] {
    return this.cdkOutOverridePaths;
  }

  public getProjectName(): string {
    return path.basename(this.projectRootFolderPath);
  }

  private normalizePath(projectRootFolderPath: string): string {
    return projectRootFolderPath.replace(/\\/g, '/').replace(/[\/\\]+$/, '');
  }

  public getProjectRootFolderPath(): string {
    return this.projectRootFolderPath;
  }

  public getSrtOutputFolderPath(): string {
    return path.join(this.projectRootFolderPath, '.srt');
  }

  public getIssuesFilePath(): string {
    return path.join(this.getSrtOutputFolderPath(), 'issues.json');
  }

  public async isCloudFormationTemplate(cloudformationTemplateFilePath: string): Promise<boolean> {
    return this.cfnValidator.isCloudFormationTemplate(this.projectRootFolderPath, cloudformationTemplateFilePath);
  }

  public async isProjectRootFolder(): Promise<boolean> {
    try {
      const files = await fs.readdir(this.projectRootFolderPath);
      return files.filter(file => file.toLowerCase() === '.git').length === 1;
    } catch (error) {
      return false;
    }
  }

  public async getCloudFormationTemplates(): Promise<CloudFormationTemplateConfig[]> {
    const srtOutputFolderPath = this.getSrtOutputFolderPath();

    if (this.cdkOutOverridePaths.length > 0) {
      const projects = this.buildCdkProjectsFromOverridePaths();
      return this.getCdkTemplatesFromProjects(projects, srtOutputFolderPath);
    }

    const cdkProjects = await this.getAllCdkProjects();

    if (cdkProjects.length > 0) {
      return this.getCdkTemplatesFromProjects(cdkProjects, srtOutputFolderPath);
    }

    return this.getStandardTemplates(srtOutputFolderPath);
  }

  public async getTerraformPlans(): Promise<TerraformProjectConfig[]> {
    const detector = new TerraformDetector(this);
    return detector.detect();
  }

  public async getAllCdkProjects(): Promise<CdkProjectConfig[]> {
    try {
      const matches = await glob('**/cdk.json', {
        ignore: this.getFolderIgnorePatterns(),
        cwd: this.getProjectRootFolderPath(),
        absolute: true,
        maxDepth: 10
      });

      const projects: CdkProjectConfig[] = [];
      for (const cdkJsonPath of matches) {
        const config = await this.buildCdkProjectConfig(cdkJsonPath);
        if (config) projects.push(config);
      }

      return projects;
    } catch (error) {
      return [];
    }
  }

  private async buildCdkProjectConfig(cdkJsonPath: string): Promise<CdkProjectConfig | null> {
    try {
      const rootPath = path.dirname(cdkJsonPath);
      const name = path.basename(rootPath);
      const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
      const cdkJson = JSON.parse(cdkJsonContent);

      const outputDir = cdkJson.output || 'cdk.out';
      const outputPath = path.join(rootPath, outputDir);

      const cdkEntrypointFile = this.cdkCommandParser.extractFromCdkJson(cdkJsonContent);
      const entrypointPath = cdkEntrypointFile ? path.join(rootPath, cdkEntrypointFile.file) : null;

      return { name, rootPath, outputPath, entrypointPath };
    } catch (error) {
      return null;
    }
  }

  private async getCdkTemplatesFromProjects(cdkProjects: CdkProjectConfig[], srtOutputFolderPath: string): Promise<CloudFormationTemplateConfig[]> {
    const allTemplates: CloudFormationTemplateConfig[] = [];
    const useProjectSubfolders = cdkProjects.length > 1;

    for (const project of cdkProjects) {
      const projectTemplates = await this.getCdkTemplatesForProject(project, srtOutputFolderPath, useProjectSubfolders);
      allTemplates.push(...projectTemplates);
    }

    return allTemplates;
  }

  private async getCdkTemplatesForProject(project: CdkProjectConfig, srtOutputFolderPath: string, useProjectSubfolder: boolean): Promise<CloudFormationTemplateConfig[]> {
    try {
      const entries = await fs.readdir(project.outputPath, { withFileTypes: true });
      const scriptPaths: string[] = [];

      for (const entry of entries) {
        if (entry.isFile() && entry.name.endsWith('.template.json')) {
          scriptPaths.push(path.join(project.outputPath, entry.name));
        }
      }

      const templateNameCounts: Record<string, number> = {};

      return scriptPaths.map(x => {
        const templateBaseName = path.basename(x).replace(".template.json", "");
        let outputFolderName = templateBaseName;

        if (templateBaseName in templateNameCounts) {
          templateNameCounts[templateBaseName]++;
          outputFolderName = `${templateBaseName}-${templateNameCounts[templateBaseName]}`;
        } else {
          templateNameCounts[templateBaseName] = 1;
        }

        const baseOutputPath = useProjectSubfolder
          ? path.join(srtOutputFolderPath, project.name)
          : srtOutputFolderPath;

        return {
          cfnTemplateName: templateBaseName,
          cfnTemplateFilePath: x,
          cfnTemplateOutputFolderPath: path.join(baseOutputPath, outputFolderName),
          cdkProjectName: project.name
        };
      });
    } catch (error) {
      return [];
    }
  }

  private validateCdkOutPaths(paths: string[]): string[] {
    const normalized = paths.map(cdkOutPath => {
      const norm = this.normalizePath(cdkOutPath);
      if (!existsSync(norm)) {
        throw new Error(`CDK output path does not exist: ${norm}`);
      }
      if (!statSync(norm).isDirectory()) {
        throw new Error(`CDK output path is not a directory: ${norm}`);
      }
      return norm;
    });
    return [...new Set(normalized)];
  }

  private buildCdkProjectsFromOverridePaths(): CdkProjectConfig[] {
    return this.cdkOutOverridePaths.map(overridePath => ({
      name: path.basename(overridePath),
      rootPath: path.dirname(overridePath),
      outputPath: overridePath,
      entrypointPath: null
    }));
  }

  private async getStandardTemplates(srtOutputFolderPath: string): Promise<CloudFormationTemplateConfig[]> {
    const excludedDirs = this.getIgnoredDirectoryNames();
    const scriptPaths: string[] = [];

    const findScripts = async (dir: string) => {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!excludedDirs.includes(entry.name)) {
            await findScripts(fullPath);
          }
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();

          if (['.yaml', '.yml', '.json'].includes(ext)) {
            if (await this.cfnValidator.isCloudFormationTemplate(this.projectRootFolderPath, fullPath)) {
              scriptPaths.push(fullPath);
            }
          }
        }
      }
    };

    await findScripts(this.projectRootFolderPath);

    return scriptPaths.map(x => {
      const templateName = path.parse(x).name;
      const relativePath = path.relative(this.projectRootFolderPath, path.dirname(x)).replace(/[\\/\\\\]/g, '-');
      let outputFolderName = templateName;
      if (relativePath) {
        outputFolderName = `${relativePath}-${templateName}`;
      }

      return {
        cfnTemplateName: templateName,
        cfnTemplateFilePath: x,
        cfnTemplateOutputFolderPath: path.join(srtOutputFolderPath, outputFolderName)
      };
    });
  }

  public async isPythonProject(): Promise<boolean> {
    try {
      const excludedDirs = this.getIgnoredDirectoryNames();
      const dirsToCheck: string[] = [this.projectRootFolderPath];

      while (dirsToCheck.length > 0) {
        const currentDir = dirsToCheck.shift()!;
        try {
          const entries = await fs.readdir(currentDir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
              if (!excludedDirs.includes(entry.name)) {
                dirsToCheck.push(fullPath);
              }
            } else if (entry.isFile() && path.extname(entry.name).toLowerCase() === '.py') {
              return true;
            }
          }
        } catch (error) {
          // Silent failure for inaccessible directories
        }
      }

      return false;
    } catch (error) {
      SrtLogger.logError('Error checking if project is Python', error as Error, { projectRootFolderPath: this.projectRootFolderPath });
      return false;
    }
  }

  public async hasJupyterNotebooks(): Promise<boolean> {
    const notebooks = await this.findJupyterNotebooks();
    return notebooks.length > 0;
  }

  public async findJupyterNotebooks(): Promise<string[]> {
    try {
      const dirsToCheck: string[] = [this.projectRootFolderPath];
      const notebookFiles: string[] = [];
      const excludedDirs = this.getIgnoredDirectoryNames();

      while (dirsToCheck.length > 0) {
        const currentDir = dirsToCheck.shift()!;
        try {
          const entries = await fs.readdir(currentDir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
              if (!excludedDirs.includes(entry.name)) {
                dirsToCheck.push(fullPath);
              }
            } else if (entry.isFile() && path.extname(entry.name).toLowerCase() === '.ipynb') {
              notebookFiles.push(fullPath);
            }
          }
        } catch (error) {
          // Silent failure for inaccessible directories
        }
      }

      return notebookFiles;
    } catch (error) {
      SrtLogger.logError('Error finding Jupyter notebooks', error as Error, { projectRootFolderPath: this.projectRootFolderPath });
      return [];
    }
  }

  public async isCdkProject(): Promise<boolean> {
    return (await this.getCdkRootFolderPath()) !== null;
  }

  public async getCdkRootFolderPath(): Promise<string | null> {
    try {
      const matches = await glob('**/cdk.json', {
        ignore: this.getFolderIgnorePatterns(),
        cwd: this.getProjectRootFolderPath(),
        absolute: true,
        maxDepth: 10
      });

      return matches.length > 0 ? path.dirname(matches[0]) : null;
    } catch (error) {
      return null;
    }
  }

  public async getCdkOutputFolderPath(): Promise<string | null> {
    try {
      const cdkRoot = await this.getCdkRootFolderPath();

      if (!cdkRoot) return null;

      const cdkJsonPath = path.join(cdkRoot, 'cdk.json');
      const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
      const cdkJson = JSON.parse(cdkJsonContent);
      const outputDir = cdkJson.output || 'cdk.out';

      return path.join(cdkRoot, outputDir);
    } catch (error) {
      return null;
    }
  }

  public async getCdkEntrypoint(): Promise<string | null> {
    try {
      const cdkRoot = await this.getCdkRootFolderPath();

      if (!cdkRoot) return null;

      const cdkJsonPath = path.join(cdkRoot, 'cdk.json');
      const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
      const cdkEntrypointFile = this.cdkCommandParser.extractFromCdkJson(cdkJsonContent);

      if (!cdkEntrypointFile) return null;

      return path.join(cdkRoot, cdkEntrypointFile.file);
    } catch (error) {
      return null;
    }
  }

  public async hasPythonVenv(): Promise<boolean> {
    const venvDir = await this.findVenvDir();
    return venvDir !== undefined;
  }

  public async getPythonVenvConfig(): Promise<PythonVenvConfig> {
    const venvDir = await this.findVenvDir();
    if (!venvDir) {
      throw new Error(`No Python virtual environment found in ${this.projectRootFolderPath}`);
    }
    return this.buildVenvConfig(venvDir);
  }

  private async findVenvDir(): Promise<string | undefined> {
    const entries = await fs.readdir(this.projectRootFolderPath, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const venvDir = path.join(this.projectRootFolderPath, entry.name);
      const pyvenvCfgPath = path.join(venvDir, 'pyvenv.cfg');

      try {
        await fs.access(pyvenvCfgPath);
        const config = this.buildVenvConfig(venvDir);
        await fs.access(config.pythonPath);
        return venvDir;
      } catch {
        continue;
      }
    }

    return undefined;
  }

  private buildVenvConfig(venvDir: string): PythonVenvConfig {
    const isWindows = process.platform === 'win32';
    const binDir = isWindows ? 'Scripts' : 'bin';
    const pythonExe = isWindows ? 'python.exe' : 'python';

    return {
      venvDir,
      binDir,
      pythonPath: path.join(venvDir, binDir, pythonExe)
    };
  }
}
