import * as path from 'path';
import * as fileUtils from '../../shared/file-system/file-utils.js';
import * as bedrockUtils from '../../shared/ai/bedrock-client.js';
import { CheckovScanner } from '../scanning/checkov/checkov-scanner.js';
import { SecurityMatrixScannerEngine } from '../scanning/security-matrix/matrix-scanner-engine.js';
import { SrtLogger } from '../../shared/logging/srt-logger.js';
import { Threat, ThreatReportGenerator } from './threat-model-report-generator.js';
import { DIAGRAM_GENERATOR_PROMPT } from './diagram-generator-prompt.js';
import { THREAT_MODEL_GENERATOR_PROMPT } from './threat-model-generator-prompt.js';
import { TemplateResult, TerraformTemplateResult } from '../types.js';
import { CloudFormationTemplateConfig, ProjectContext } from '../../shared/project/project-context.js';
import { TerraformProjectConfig } from '../../shared/terraform/types.js';

export class TemplateCoordinator {
	constructor(
		private readonly context: ProjectContext,
		private generateDiagram: boolean,
		private generateThreatModel: boolean,
		private onProgress: (progress: string) => void = () => { }
	) { }

	public async processTemplates(): Promise<TemplateResult[]> {
		const cfnTemplates = await this.context.getCloudFormationTemplates();
		const templateResults = cfnTemplates.length > 0
			? await Promise.all(cfnTemplates.map(input => this.processTemplate(input)))
			: [];

		return templateResults;
	}

	public async processTerraformPlans(): Promise<TerraformTemplateResult[]> {
		const tfPlans = await this.context.getTerraformPlans();
		if (tfPlans.length === 0) return [];

		const results = await Promise.all(tfPlans.map(plan => this.processTerraformPlan(plan)));
		return results;
	}

	private async processTerraformPlan(tfProject: TerraformProjectConfig): Promise<TerraformTemplateResult> {
		const result: TerraformTemplateResult = {
			tfProjectName: tfProject.name,
			tfProjectRootPath: tfProject.rootPath,
			tfOutputFolderPath: tfProject.outputFolderPath,
			checkovSummaryPath: null,
			terraformMatrixPath: null,
			diagramPath: null,
			threatModelPath: null
		};

		const [checkovSummaryPath, terraformMatrixPath] = await Promise.all([
			this.executeTerraformCheckovScan(tfProject),
			this.executeTerraformMatrixScan(tfProject)
		]);

		result.checkovSummaryPath = checkovSummaryPath;
		result.terraformMatrixPath = terraformMatrixPath;

		return result;
	}

	private async executeTerraformMatrixScan(tfProject: TerraformProjectConfig): Promise<string | null> {
		try {
			this.onProgress(`  › Starting terraform matrix scan for ${tfProject.name}...`);

			const scanner = new SecurityMatrixScannerEngine();
			const filePath = path.join(tfProject.outputFolderPath, 'terraform-matrix.json');
			const success = await scanner.runTerraform(tfProject.name, tfProject.planJsonPath, filePath);

			this.onProgress(`  ✔ Completed terraform matrix scan for ${tfProject.name}`);
			return success ? filePath : null;
		} catch (error) {
			this.onProgress(`  ✗ Failed terraform matrix scan for ${tfProject.name}`);
			SrtLogger.logError('Error running terraform matrix scan', error as Error);
			return null;
		}
	}

	private async executeTerraformCheckovScan(tfProject: TerraformProjectConfig): Promise<string | null> {
		try {
			this.onProgress(`  › Starting Checkov scan for ${tfProject.name}...`);

			const checkovScanner = new CheckovScanner();
			const summaryPath = await checkovScanner.runTerraform(
				this.context.getProjectRootFolderPath(),
				tfProject.rootPath,
				tfProject.outputFolderPath
			);

			if (summaryPath) {
				this.onProgress(`  ✔ Completed Checkov scan for ${tfProject.name}`);
			} else {
				this.onProgress(`  ✗ Failed Checkov scan for ${tfProject.name}`);
			}

			return summaryPath;
		} catch (error) {
			this.onProgress(`  ✗ Failed Checkov scan for ${tfProject.name}`);
			SrtLogger.logError('Error during Terraform Checkov scan', error as Error);
			return null;
		}
	}

	private async processTemplate(cfnTemplate: CloudFormationTemplateConfig): Promise<TemplateResult> {
		const result: TemplateResult = {
			cfnTemplateName: cfnTemplate.cfnTemplateName,
			cfnTemplateFilePath: cfnTemplate.cfnTemplateFilePath,
			cfnTemplateOutputFolderPath: cfnTemplate.cfnTemplateOutputFolderPath,
			cdkProjectName: cfnTemplate.cdkProjectName,
			checkovSummaryPath: null,
			securityMatrixPath: null,
			diagramPath: null,
			threatModelPath: null
		};

		const templateContents = await this.getCloudFormationTemplateFileContents(cfnTemplate.cfnTemplateFilePath);
		const displayName = this.getTemplateDisplayName(cfnTemplate);

		const [diagramPath, threatModelPath, checkovSummaryPath, securityMatrixPath] = await Promise.all([
			this.generateDiagramArtifact(displayName, templateContents, cfnTemplate.cfnTemplateOutputFolderPath),
			this.generateThreatModelArtifact(displayName, templateContents, cfnTemplate.cfnTemplateOutputFolderPath),
			this.executeCheckovScan(cfnTemplate, displayName),
			this.executeSecurityMatrixScan(cfnTemplate, displayName)
		]);

		result.diagramPath = diagramPath;
		result.threatModelPath = threatModelPath;
		result.checkovSummaryPath = checkovSummaryPath;
		result.securityMatrixPath = securityMatrixPath;

		return result;
	}

	private async getCloudFormationTemplateFileContents(templateFilePath: string): Promise<string> {
		const content = await fileUtils.readTextFile(templateFilePath);
		return content || '';
	}

	private getTemplateDisplayName(cfnTemplate: CloudFormationTemplateConfig): string {
		return cfnTemplate.cdkProjectName
			? `${cfnTemplate.cdkProjectName}/${cfnTemplate.cfnTemplateName}`
			: cfnTemplate.cfnTemplateName;
	}

	private async generateDiagramArtifact(displayName: string, templateContents: string, outputFolderPath: string): Promise<string | null> {
		if (!this.generateDiagram) return null;

		try {
			this.onProgress(`  › Generating data flow diagram for ${displayName}...`);

			const result = await bedrockUtils.sendPrompt(DIAGRAM_GENERATOR_PROMPT, templateContents, this.onProgress);
			const filePath = path.join(outputFolderPath, 'diagram.md');

			await this.saveArtifact(result, filePath);

			this.onProgress(`  ✔ Generated data flow diagram for ${displayName}`);

			return filePath;
		} catch (error) {
			this.onProgress(`  ✗ Failed to generate data flow diagram for ${displayName}`);
			SrtLogger.logError('Error generating diagram', error as Error);
			return null;
		}
	}

	private async generateThreatModelArtifact(displayName: string, templateContents: string, outputFolderPath: string): Promise<string | null> {
		if (!this.generateThreatModel) return null;

		try {
			this.onProgress(`  › Generating threat model for ${displayName}...`);

			const stackName = path.basename(outputFolderPath);
			const prompt = THREAT_MODEL_GENERATOR_PROMPT
				.replaceAll("{{CLOUDFORMATION_TEMPLATE_NAME}}", stackName)
				.replaceAll("{{CLOUDFORMATION_TEMPLATE_NAME_UPPER_CASE}}", stackName.toUpperCase());

			const result = await bedrockUtils.sendPrompt(prompt, templateContents, this.onProgress);
			const filePath = path.join(outputFolderPath, 'threat-model.json');
			await this.saveArtifact(result, filePath);

			const threats = await fileUtils.readJsonFile<Threat[]>(filePath);
			if (threats) {
				const threatReportGenerator = new ThreatReportGenerator();
				const report = threatReportGenerator.generateReport(threats, 'threat-model.md');
				await this.saveArtifact(report, path.join(outputFolderPath, 'threat-model-report.md'));
			}

			this.onProgress(`  ✔ Generated threat model for ${displayName}`);

			return filePath;
		} catch (error) {
			this.onProgress(`  ✗ Failed to generate threat model for ${displayName}`);
			SrtLogger.logError('Error generating threat model', error as Error);
			return null;
		}
	}

	private async executeCheckovScan(cfnTemplate: CloudFormationTemplateConfig, displayName: string): Promise<string | null> {
		this.onProgress(`  › Starting Checkov scan for ${displayName}...`);

		const checkovScanner = new CheckovScanner();
		const summaryPath = await checkovScanner.run(
			this.context.getProjectRootFolderPath(),
			cfnTemplate.cfnTemplateFilePath,
			cfnTemplate.cfnTemplateOutputFolderPath
		);

		if (summaryPath) {
			this.onProgress(`  ✔ Completed Checkov scan for ${displayName}`);
		} else {
			this.onProgress(`  ✗ Failed Checkov scan for ${displayName}`);
		}

		return summaryPath;
	}

	private async executeSecurityMatrixScan(cfnTemplate: CloudFormationTemplateConfig, displayName: string): Promise<string | null> {
		try {
			this.onProgress(`  › Starting security matrix scan for ${displayName}...`);

			const securityMatrixScanner = new SecurityMatrixScannerEngine();
			const filePath = path.join(cfnTemplate.cfnTemplateOutputFolderPath, 'security-matrix.json');
			const success = await securityMatrixScanner.run(this.context.getProjectRootFolderPath(), cfnTemplate.cfnTemplateFilePath, filePath);

			this.onProgress(`  ✔ Completed security matrix scan for ${displayName}`);

			if (success) {
				return filePath;
			} else {
				return null;
			}
		} catch (error) {
			this.onProgress(`  ✗ Failed security matrix scan for ${displayName}`);
			SrtLogger.logError('Error generating security matrix', error as Error);
			return null;
		}
	}

	private async saveArtifact(artifactContents: string, artifactFilePath: string): Promise<void> {
		await fileUtils.ensureDirectoryExists(path.dirname(artifactFilePath));
		await fileUtils.writeTextFile(artifactFilePath, artifactContents);
	}
}
