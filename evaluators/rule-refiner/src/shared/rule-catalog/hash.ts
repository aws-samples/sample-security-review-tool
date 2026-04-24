import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

export function sha256OfFile(absolutePath: string): string {
    const contents = fs.readFileSync(absolutePath);
    return crypto.createHash('sha256').update(contents).digest('hex');
}

export function sha256OfString(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
}
