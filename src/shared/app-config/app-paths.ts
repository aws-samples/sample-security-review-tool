import path from 'path';

export class AppPaths {
    public static getAppDir(): string {
        return process.env.SRT_APP_DIR ?? path.dirname(process.execPath);
    }
}
