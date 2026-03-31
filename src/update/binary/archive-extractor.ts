import * as fs from 'fs';
import * as path from 'path';
import AdmZip from 'adm-zip';
import * as tar from 'tar';

export class ArchiveExtractor {
    public static async extract(archivePath: string, extractDir: string): Promise<string | null> {
        if (!fs.existsSync(extractDir)) {
            fs.mkdirSync(extractDir, { recursive: true });
        }

        let extractSuccess = false;

        if (archivePath.endsWith('.tar.gz')) {
            try {
                await tar.extract({
                    file: archivePath,
                    cwd: extractDir
                });
                extractSuccess = true;
            } catch (tarError) {
                return null;
            }
        } else if (archivePath.endsWith('.zip')) {
            try {
                const zip = new AdmZip(archivePath);
                zip.extractAllTo(extractDir, true);
                extractSuccess = true;
            } catch (zipError) {
                return null;
            }
        }

        if (!extractSuccess) {
            return null;
        }

        const extractedFiles = fs.readdirSync(extractDir);
        const binaryFile = extractedFiles.find(file =>
            file === 'srt' || file === 'srt.exe' || (file.startsWith('srt') && !file.includes('.'))
        );

        if (!binaryFile) {
            return null;
        }

        return path.join(extractDir, binaryFile);
    }
}
