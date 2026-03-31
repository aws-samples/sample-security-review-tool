import * as fs from 'fs/promises';

export class NodeFileWriter {
    public async write(filePath: string, content: string): Promise<void> {
        await fs.writeFile(filePath, content, 'utf-8');
    }

    public async writeTextFile(filePath: string, content: string): Promise<boolean> {
        try {
            await fs.writeFile(filePath, content, 'utf-8');
            return true;
        } catch (error) {
            return false;
        }
    }
}
