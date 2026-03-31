import { Command } from "commander";
import { AssessCommand } from "./assess/command.js";
import { ConfigCommand } from "./config/command.js";
import { FixCommand } from "./fix/command.js";
import { ConfigLoader } from "./shared/app-config/config-loader.js";
import { PostHogClient } from "./shared/analytics/posthog-client.js";
import { SrtLogger } from "./shared/logging/srt-logger.js";
import { StatusCommand } from "./status/command.js";
import { UpdateCommand } from "./update/command.js";
import { ReleaseChecker } from "./update/release/release-checker.js";

SrtLogger.initialize();
PostHogClient.initialize();
PostHogClient.capture('cli-user', 'test_event', { property: 'value' });

const program = new Command();

program.version(ReleaseChecker.getCurrentVersion());

// Workaround for Bun cross-compilation bug that injects executable path as argv[2]
if (
    process.argv.length >= 3 &&
    (process.argv[2] === process.execPath ||
        process.argv[2] === "./srt" ||
        process.argv[2] === "srt")
) {
    process.argv.splice(2, 1);
}

AssessCommand.register(program);
FixCommand.register(program);
StatusCommand.register(program);
ConfigCommand.register(program);
UpdateCommand.register(program);

program.hook("preAction", async (_thisCommand, actionCommand) => {
    const commandName = actionCommand.name();

    await ConfigLoader.load();

    if (commandName !== "update") {
        await ReleaseChecker.startBackgroundCheck();
    }
});

program.hook("postAction", async (_thisCommand, actionCommand) => {
    const commandName = actionCommand.name();

    if (commandName !== "update") {
        ReleaseChecker.showUpdateNotificationIfAvailable();
    }
});

await program.parseAsync();
await PostHogClient.shutdown();
