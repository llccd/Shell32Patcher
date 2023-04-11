# Classic Context Menu for Windows 11

Shell32Patcher allows you to use classic context menu in Windows 11 file explorer.

This repo demonstrates a method for persist program patching without using DLL hijack or function hook. For end users, it's more convenient to use the registry tweak in `Regs` folder. `TrustedInstaller` rights is needed for 'AllUsers' registry tweak.

## Usage

### Non-persist patch

Uncheck 'Launch folder windows in a separate process'

Run program. The patch will take effect immediately and apply to your current session only

Newly started explorer.exe remains unpatched. To revert, simply restart explorer.exe

### Systemwide patch

**Note: Systemwide patch will not work after July 2022 update. Because the mechanism it uses, which is the same as [PPLdump](https://github.com/itm4n/PPLdump), is blocked by this update.**

To perform systemwide patch, you need to run program using an administrative account (but **not** `NT AUTHORITY\SYSTEM`) with command line option `-p`

The patch will apply to all users and all newly started processes

To revert systemwide patch, you must restart your computer

## FAQ

### Context menu on desktop is still in new style

You may have some program that takes over processing of desktop items (like desktop organizers). In that case, the context menu is not handled by explorer. You can try command line option `-a` which will patch all applications to see if it works.
