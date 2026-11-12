---
icon: lucide/settings
---

Ragers uses a file named `.ragers.yaml` in order to track the file you wish to encrypt, who may decrypt those files, and how you wish to encrypt them. This part of the documentation teaches you more in detail how Ragers interpret your configuration file and how to use it efficiently.

## How configuration is looked up

Ragers is not regarded as a tool to be used system-wide, but only project-scoped. Hence, config files are only searched through based on your current working directory.

--8<-- "not-implemented.md"

Configuration files are looked up from your root directory, down to your current working directory. This mean that Ragers will start looking for a file called `.ragers.yaml` (or `.yml`) starting from your filesystem's root, and look for more until it reach your current working directory.

All files found are then merged in that same order, meaning the file it found last will be winning in case there are conflict in definitions.

!!! note

    If both `.ragers.yaml` and `.ragers.yml` exists in the same directory, `.ragers.yaml` takes priority and its `.yml` counterpart will be ignored.


## How configurations is loaded and checked

When a configuration file is loaded, it is immediately checked for errors.
The done checks are:

- Check that all defined age recipients are valid and unique
- Check that all defined file paths are valid and exists
- Check groups does not contain undefined recipients
- Check that files are unique in source
- Check that files are unique in output
- Check that files not contain undefined recipients

If one of those check fail, the configuration file is rejected and Ragers will refuse to load it, and exit until it can be read.
