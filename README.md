# Classic Context Menu for Windows 11

Shell32Patcher allows you to use classic context menu in Windows 11 file explorer.

## Usage

### Non-persist patch

Uncheck 'Launch folder windows in a separate process'

Run program. The patch will take effect immediately and apply to your current session only

Newly started explorer.exe remains unpatched. To revert, simply restart explorer.exe

### Systemwide patch

To perform systemwide patch, you need to run program using an administrative account (but **not** `NT AUTHORITY\SYSTEM`) with commandline option `-p`

The patch will apply to all users and all newly started processes

To revert systemwide patch, you must restart your computer
