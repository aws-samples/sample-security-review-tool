import * as fs from 'fs/promises';
import * as path from 'path';
import { GitIgnoreToGlob } from './gitignore-to-glob.js';

const STANDARD_IGNORE_DIRS = [
  '.srt',
  '.dsr',
  'node_modules',
  'vendor',
  'bin',
  'obj',
  'dist',
  'build',
  '.git',
  '.svn',
  '.hg',
  '.vscode',
  '.github',
  'cdk.out',
  '.env',
];

export class IgnorePatternService {
  private directoryNames: string[] = [];
  private gitignoreGlobPatterns: string[] = [];
  private initialized = false;

  constructor(private readonly projectRootFolderPath: string) {}

  public static async create(projectRootFolderPath: string): Promise<IgnorePatternService> {
    const service = new IgnorePatternService(projectRootFolderPath);
    await service.initialize();
    return service;
  }

  public async initialize(): Promise<void> {
    const gitIgnoreToGlob = new GitIgnoreToGlob(this.projectRootFolderPath);
    this.gitignoreGlobPatterns = gitIgnoreToGlob.read();

    const gitignoreDirNames = this.extractDirectoryNames(this.gitignoreGlobPatterns);
    const venvDirNames = await this.detectVenvDirectories();
    this.directoryNames = [...new Set([...STANDARD_IGNORE_DIRS, ...venvDirNames, ...gitignoreDirNames])];

    this.initialized = true;
  }

  public getDirectoryNames(): string[] {
    this.ensureInitialized();
    return [...this.directoryNames];
  }

  private extractDirectoryNames(globPatterns: string[]): string[] {
    return globPatterns
      .filter(pattern => !pattern.startsWith('!'))
      .map(pattern => pattern.replace(/^\*\*\//, '').replace(/\/\*\*$/, ''))
      .filter(name => !name.includes('/') && !name.includes('*'))
      .filter(name => name.length > 0);
  }

  public getGlobPatterns(): string[] {
    this.ensureInitialized();
    const dirGlobs = this.directoryNames.map(name => `**/${name}/**`);
    return [...new Set([...dirGlobs, ...this.gitignoreGlobPatterns])];
  }

  private async detectVenvDirectories(): Promise<string[]> {
    const venvNames: string[] = [];
    try {
      const entries = await fs.readdir(this.projectRootFolderPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const pyvenvCfgPath = path.join(this.projectRootFolderPath, entry.name, 'pyvenv.cfg');
        try {
          await fs.access(pyvenvCfgPath);
          venvNames.push(entry.name);
        } catch {
          // Not a venv directory
        }
      }
    } catch {
      // Silent failure for inaccessible project root
    }
    return venvNames;
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('IgnorePatternService must be initialized before use. Call initialize() first.');
    }
  }
}
