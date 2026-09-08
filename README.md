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

The author declares that few AI has been used to write the project. The majority of the code has been written by themselves with the help of AI only for initial implementation of a few final parts of the application. However, AI is not the main way of production to realize this application and is only used as an assisting tool.

Basically, [it's brain-made](https://brainmade.org/).

If the code is shit, well, it's my fault, not Claude's.
But hey, it could have been written in Python instead. Wink wink.
