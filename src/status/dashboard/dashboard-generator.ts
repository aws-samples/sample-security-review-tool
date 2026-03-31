import * as path from 'path';
import { writeTextFile } from '../../shared/file-system/file-utils.js';
import { DashboardDataTransformer } from './dashboard-data.js';
import { DashboardTemplate } from './dashboard-template.js';
import { DashboardOptions } from './types.js';

export class DashboardGenerator {
    private readonly dataTransformer = new DashboardDataTransformer();
    private readonly template = new DashboardTemplate();

    public async generate(options: DashboardOptions): Promise<string> {
        const data = await this.dataTransformer.transform(options, options.showAll ?? false);
        const html = this.template.render(data);

        const outputPath = path.join(options.srtFolderPath, 'dashboard.html');
        await writeTextFile(outputPath, html);

        return outputPath;
    }
}
