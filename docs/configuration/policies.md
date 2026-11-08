---
description: Policies defines default behaviors of Ragers during encryption/decryption. This page lists possible options you can use to configure those behaviours to your liking.
icon: lucide/scroll-text
---

--8<-- "draft-feature.md"

Policies defines the default behavior to use when encrypting a file. Currently, only `armor` is supported.

Policies are defined at the top-level of your config file:

```yaml
policies:
    # Policies...
```

## Available policies - reference

### `armor`

Define if files shall be encrypted using the an armored-file format, or be encrypted in binary format.
Setting this policy to `true` will make all files be encrypted in armor format.

Default: `false`

!!! info

    This can be overriden per-file using the corresponding `armor` setting.
