import { execSync } from "node:child_process";
import { mkdirSync, readdirSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";

const TARGETS: Record<string, { bunTarget: string; outfile: string }> = {
    "linux-x64": { bunTarget: "bun-linux-x64", outfile: "build/linux-x64/srt" },
    "linux-arm64": {
        bunTarget: "bun-linux-arm64",
        outfile: "build/linux-arm64/srt",
    },
    "osx-x64": { bunTarget: "bun-darwin-x64", outfile: "build/osx-x64/srt" },
    "osx-arm64": {
        bunTarget: "bun-darwin-arm64",
        outfile: "build/osx-arm64/srt",
    },
    "win-x64": {
        bunTarget: "bun-windows-x64",
        outfile: "build/win-x64/srt.exe",
    },
};

function main(): void {
    const [target] = process.argv.slice(2);

    if (!target || !TARGETS[target]) {
        console.error(
            `Usage: bun scripts/build-cli.ts <${Object.keys(TARGETS).join("|")}>`,
        );
        process.exit(1);
    }

    const { bunTarget, outfile } = TARGETS[target];

    const command = [
        "bun build src/index.ts",
        "--compile",
        "--minify",
        "--sourcemap",
        `--target=${bunTarget}`,
        `--outfile ${outfile}`,
    ].join(" ");

    const projectRoot = resolve(import.meta.dir, "..");

    console.log(`Building ${target}...`);
    execSync(command, { stdio: "inherit", cwd: projectRoot });

    // Move Bun compilation temp files to .bun-builds/
    try {
        const bunBuildsDir = join(projectRoot, ".bun-builds");
        mkdirSync(bunBuildsDir, { recursive: true });
        for (const file of readdirSync(projectRoot)) {
            if (file.endsWith(".bun-build")) {
                renameSync(join(projectRoot, file), join(bunBuildsDir, file));
            }
        }
    } catch {
        // Ignore cleanup errors
    }
}

main();
