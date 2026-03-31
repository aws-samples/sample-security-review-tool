import chalk from 'chalk';
import ora, { Ora } from 'ora';

export const ui = {
	ok: chalk.green('✔'),
	fail: chalk.red('✗'),
	warn: chalk.yellow('!'),
	info: chalk.blue('·'),
	arrow: chalk.dim('›'),

	success: (msg: string) => `${chalk.green('✔')} ${msg}`,
	error: (msg: string) => `${chalk.red('✗')} ${msg}`,
	warning: (msg: string) => `${chalk.yellow('!')} ${msg}`,
	hint: (msg: string) => `${chalk.blue('·')} ${msg}`,
	step: (msg: string) => `  ${chalk.dim('›')} ${msg}`,
	substep: (msg: string) => `    ${chalk.dim('›')} ${msg}`,

	header: (msg: string) => chalk.bold(msg),
	section: (msg: string) => `\n${chalk.bold(msg)}`,
	dimmed: (msg: string) => chalk.dim(msg),

	spinner: (msg: string): Ora => ora({ text: msg, spinner: 'dots' }),
};
