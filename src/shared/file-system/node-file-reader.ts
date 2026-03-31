import * as fs from 'fs/promises';

export class NodeFileReader {
    public async read(filePath: string): Promise<string> {
        return await fs.readFile(filePath, 'utf-8');
    }

    public async readTextFile(filePath: string): Promise<string | null> {
        try {
            return await fs.readFile(filePath, 'utf-8');
        } catch (error) {
            return null;
        }
    }

    public async readJsonFile<T>(filePath: string): Promise<T | null> {
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            return JSON.parse(content) as T;
        } catch (error) {
            return null;
        }
    }
}
