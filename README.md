# Ragers: Rust Age's Repository Solution

`ragers` is a CLI tool aimed at DevOps individuals and teams to collaborate easily using age's encrypted file format, most especially while working in public repositories.

It features its own config file, `.ragers.yaml`, where you define which files you wish to encrypt, and whom is able to decrypt them.
It uses the age's crate, so there is no commands dependency and is (hopefully!) interopeable with the original age's CLI.

The format specification is at <https://age-encryption.org/v1>. The original age implementation was designed by @Benjojo and @FiloSottile. 

This take a similar path to [agebox](<https://github.com/slok/agebox>). It's an alternative, a solution perhaps almost one-to-one.

My cat duly recommend the usage of Ragers only once v1.0 hit the streets.

## State

A simple projet management board can be found here: <https://sites.plane.so/issues/44ee0d0a1bcb490b81f56907fb46e47f>

Plugins are NOT supported or intended for the moment being.

This tool is currently English only.

Only standard age X55219 and SSH (recipient-based) encryption will be supported.

---

> [!CAUTION]
> This is my first ever CLI (so published package), and my first Rust project, on top of that. Packages releases may not be a complete thing. I am learning, trying new things out.
>
> Help from new packagers is appreciated and welcome. 

---

AI Disclaimer:

The author declares that no AI has been used to write in the entirety or part of the codebase. Help as been obtained for the only purpose of teaching certain aspect of Rust and for refactoring advices, without allowing the AI to write into the codebase. Human review is the only source of code.

Basically, [it's brain-made](https://brainmade.org/). Though my personal sensibility to AI's hate is... nuanced.

If the code is shit, well, it's my fault lol.
But hey, I could have written entirely in Python instead. Wink wink.
