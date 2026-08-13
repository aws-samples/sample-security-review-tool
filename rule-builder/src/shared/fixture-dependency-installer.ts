import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { RuleBuilderLogger } from './logging/rule-builder-logger.js';

const INSTALL_TIMEOUT_MS = 300_000;

/**
 * A fixture scaffold carrying a package.json needs its own node_modules: fixtures
 * live under the SRT root, so Node resolves upward into the SRT dependencies and
 * never sideways into rule-builder's, where aws-cdk-lib is installed. Terraform
 * fixtures need nothing installed: they are validated with `terraform fmt` only.
 */
export class FixtureDependencyInstaller {
    private readonly logger = new RuleBuilderLogger();

    constructor(private readonly fixtureFolderPath: string, private readonly label: string) { }

    public ensureInstalled(): void {
        if (!this.hasManifest() || this.isInstalled()) return;
        this.install();
    }

    private hasManifest(): boolean {
        return fs.existsSync(path.join(this.fixtureFolderPath, 'package.json'));
    }

    private isInstalled(): boolean {
        return fs.existsSync(path.join(this.fixtureFolderPath, 'node_modules'));
    }

    private install(): void {
        this.logger.substep(`installing ${this.label} fixture dependencies`);
        const result = spawnSync('npm', [this.installCommand(), '--no-audit', '--no-fund'], {
            cwd: this.fixtureFolderPath,
            encoding: 'utf8',
            timeout: INSTALL_TIMEOUT_MS,
        });

        if (result.status === 0) return;
        const output = (result.stdout ?? '') + (result.stderr ?? '');
        throw new Error(`Failed to install ${this.label} fixture dependencies in ${this.fixtureFolderPath}.\n${output}`);
    }

    private installCommand(): string {
        return fs.existsSync(path.join(this.fixtureFolderPath, 'package-lock.json')) ? 'ci' : 'install';
    }
}
