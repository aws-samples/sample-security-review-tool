# Adding SRT CLI to your PATH

This guide provides instructions for adding the SRT CLI to your system PATH on different operating systems.

## macOS

1. Open Terminal
2. Determine which shell you're using by running `echo $SHELL`
3. For bash shell, edit `~/.bash_profile` or `~/.bashrc`
4. For zsh shell (default in newer macOS), edit `~/.zshrc`
5. Add the following line to the file, replacing the example path with your actual installation directory:
   ```bash
   export PATH="$PATH:/path/to/srt-cli-directory"
   ```
   **Example:**
   ```bash
   # In ~/.zshrc
   export PATH="$PATH:/Users/janesmith/Desktop"
   ```
6. Save the file and run `source ~/.zshrc` (or appropriate file) to apply changes immediately
7. Verify the installation by running:
   ```bash
   srt --version
   ```

## Windows

1. Open the Start menu and search for "Environment Variables"
2. Click on "Edit the system environment variables"
3. In the System Properties window, click on the "Environment Variables" button
4. In the Environment Variables window, under "System variables", find the "Path" variable and select it
5. Click "Edit"
6. Click "New" and add the full path to the directory containing the SRT CLI executable:
   ```bash
   C:\path\to\srt-cli-directory
   ```
   **Example:**
   ```bash
   C:\Users\janesmith\Downloads
   ```
7. Click "OK" on all windows to save the changes
8. Restart any open command prompt windows for the changes to take effect
9. Verify the installation by opening a new Command Prompt and running:
   ```cmd
   srt --version
   ```

## Linux

1. Open a terminal
2. Edit your shell configuration file (`~/.bashrc`, `~/.zshrc`, or similar depending on your shell)
3. Add the following line to the file, replacing the example path with your actual installation directory:
   ```bash
   export PATH="$PATH:/path/to/srt-cli-directory"
   ```
   **Example:**
   ```bash
   # In ~/.bashrc
   export PATH="$PATH:/opt/srt-cli"
   ```
4. Save the file and run `source ~/.bashrc` (or appropriate file) to apply changes immediately
5. Verify the installation by running:
   ```bash
   srt --version
   ```

## Troubleshooting

If you've added the SRT CLI to your PATH but still can't run the `srt` command, try these steps:

1. Verify the directory contains the SRT executable:
   - macOS/Linux: `ls -la /path/to/srt-cli-directory`
   - Windows: `dir C:\path\to\srt-cli-directory`

2. Check if the PATH was updated correctly:
   - macOS/Linux: `echo $PATH`
   - Windows: `echo %PATH%` (Command Prompt) or `$env:Path` (PowerShell)

3. Make sure the executable has the correct permissions:
   - macOS/Linux: `chmod +x /path/to/srt-cli-directory/srt`
