---
icon: lucide/user-key
---

# Recipients

Recipients defines the persons or machines who have the ability to decrypt files.
Their keys are defined once in the config file, and are re-used through aliases, avoiding duplication of keys, making easy to update or revoke access.

Recipients can be define either directly in Ragers's own config file, or in an external file containing a list of public key.

Recipients can be grouped together, to easily reuse a pair of recipients for different files.

## Defining recipients

There are two ways to define recipients:

1. Directly into `.ragers.yaml`, by setting their alias and key (a [direct recipient](<#recipients>))
2. By defining one or multiple recipients in a file that contain public keys (age recipients) (a [file recipients](<#recipientsfiles>))

Those recipients are used in the config by their "aliases".

### Aliases

There are currently three kind of aliases

1. Direct recipients alias

    Those alias are simply the key of the recipient set in `recipients`. A direct recipient with key `user` has its alias set to `user`.

2. File recipient alias

    This alias is made by prefixing its key with `file:`. A file recipient with key `keys` has its alias set to `file:keys`.

3. Group recipients alias

    This alias is made by prefixing its key with `group:`. A file recipient with key `admin` has its alias set to `group:admin`.

Those aliases are used for files defined in [`files.[x].recipients`](/configuration/files#filesxrecipients).

This is an example on how aliases are used:

```yaml
$schema: "schema/config-v1.jsonc"

recipients:
  sutaai: age1uq...
  github-runner: age1he...
  contributor1: age1wh...

  groups:
    ci-access:
      - sutaai
      - github-runner
      # You can use a file alias here just as well!
      #- file:test1

  files:
    test1: my-recipients.txt

files:
  - src: File1.txt
    recipients:
      - sutaai
      - contributor1
      # Only "sutaai" and "contributor1" will be able to decrypt the file

  - src: File2.txt
    recipients:
      - file:test1
      # age recipients defined in "my-recipients.txt" will be able to decrypt the file

  - src: File3.txt
    recipients:
      - group:ci-access
      # Only "sutaai" and "github-runner" will be able to decrypt the file
```

## Reference

### `recipients`

Define a direct recipient.

The value of the direct recipient must be a valid age public key (either X25519, hybrid ML-KEM-768 + X25519 (currently unimplemented), or SSH).

Direct recipient's alias **CANNOT** be named: `groups` OR `files`, as they'll be interpreted as a [group recipient](#recipientsgroups) or [file recipient](#recipientsfiles), which are different ways to define recipients.

Their alias is represented by the key they are defined as. See [aliases](<#aliases>).

Example:

```yaml
recipients:
  sutaai: age100y4...
  # Alias

files:
  - src: myfile.txt
    recipients:
      - sutaai  # Referenced by alias
```

### `recipients.files`

Define a file recipient.

The value of the direct recipient must be point to a valid file containing recipients, as defined by age "recipient files" feature:
> Recipient files contain one or more recipients, one per line. Empty lines and lines starting with "#" are ignored as comments.

Their alias is represented by prefixing their keys by `file:`. See [aliases](<#aliases>).

Example:

```yaml
recipients:
  files:
    receivers: my-recipients.txt

files:
  - src: myfile.txt
    recipients:
      - file:receivers  # Referenced by alias
```

### `recipients.groups`

Define a group recipient.

The value of the group recipient is a list of either direct recipient alias or file recipient alias.

Their alias is represented by prefixing their keys by `group:`. See [aliases](<#aliases>).

Example:

```yaml
recipients:
  sutaai: age100y4...

  files:
    receivers: my-recipients.txt

  groups:
    admin:
      - sutaai
      - file:receivers

files:
  - src: myfile.txt
    recipients:
      - group:admin  # Referenced by alias
```
