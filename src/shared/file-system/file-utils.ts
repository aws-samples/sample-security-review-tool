import * as fs from 'fs/promises';
import * as path from 'path';

export async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    return JSON.parse(content) as T;
  } catch (error) {
    return null;
  }
}

export async function writeJsonFile<T>(filePath: string, data: T): Promise<boolean> {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (error) {
    return false;
  }
}

export async function readTextFile(filePath: string): Promise<string | null> {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch (error) {
    return null;
  }
}

export async function writeTextFile(filePath: string, content: string): Promise<boolean> {
  try {
    await fs.writeFile(filePath, content, 'utf8');
    return true;
  } catch (error) {
    return false;
  }
}

export async function findFiles(rootDir: string, fileNamePattern: string | RegExp): Promise<string[]> {
  const matchingFiles: string[] = [];

  const searchDir = async (dir: string) => {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory() && !['node_modules', '.git'].includes(entry.name)) {
          await searchDir(fullPath);
        } else if (entry.isFile()) {
          if (typeof fileNamePattern === 'string' && entry.name === fileNamePattern) {
            matchingFiles.push(fullPath);
          } else if (fileNamePattern instanceof RegExp && fileNamePattern.test(entry.name)) {
            matchingFiles.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Silent failure for inaccessible directories
    }
  };

  await searchDir(rootDir);
  return matchingFiles;
}

export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function ensureDirectoryExists(dirPath: string): Promise<boolean> {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    return true;
  } catch (error) {
    return false;
  }
}
