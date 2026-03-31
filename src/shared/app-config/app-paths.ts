import path from 'path';

export class AppPaths {
    public static getAppDir(): string {
        return path.dirname(process.execPath);
    }
}
