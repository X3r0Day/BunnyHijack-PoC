<img src="assets/demo.gif" width="100%">

# BunnyHijack: Making Bun's `trustedDependencies` Completely Useless

> [!IMPORTANT]
> **Affected**: Before rust port to `1.3.14` (latest at time of writing)
>
> **Status**: Disclosed to Oven. Maintainer declined, says this is not a vulnerability (see [Maintainer Response](#maintainer-response))
>
> **Author**: [@X3r0Day](https://github.com/X3r0Day)

---

## Summary

Bun's `trustedDependencies` system exists to protect users: only packages that are explicitly trusted (or on a built-in allowlist of packages) are allowed to run lifecycle scripts during `bun install`. The promise is simple: running `bun install` on an untrusted package should not run any of its code.

BunnyHijack makes `trustedDependencies` completely useless.

A malicious package with zero lifecycle scripts (nothing for the trust system to block) can hijack system commands for every trusted package on the system using nothing more than its `bin` field. Bun will symlink attacker code into `node_modules/.bin` and prepend that directory to `PATH` for every lifecycle script that runs. Any trusted package that calls `node`, `sh`, `make`, `curl`, or any other system command will quietly run the attacker's payload instead.

The attacker's package does not need to be trusted. It does not need its own scripts to run. It just needs a `bin` entry that shadows a system command, plus a dependency on any default-trusted package whose postinstall calls that command.

> [!NOTE]
> The trust system does nothing here. `bun i evil-pkg` in an empty directory (no `--trust` flag, no config changes) is enough to run arbitrary code with the victim's full user privileges. `trustedDependencies` offers zero protection against this.

---

## Details

Bun creates `node_modules/.bin/<name>` symlinks for every package that has a `bin` field. These symlinks are created during extraction, before any scripts run. The trust system never looks at them.

Later, when any lifecycle script runs, Bun walks up from the package directory and prepends every `node_modules/.bin` it finds to PATH. If an attacker's package declared `"bin": {"node": "./payload"}`, then `node_modules/.bin/node` points to attacker code. When a trusted package's postinstall calls `node`, the shell finds it in `.bin/` first.

Four things combine to make this work:

1. `normalized_bin_name()` in `src/install/bin.rs` strips path separators (`/`, `\`, `:`) and rejects `.` and `..`. But it lets `node`, `sh`, `bash`, `make`, `gcc`, `curl`, `git`, and every other system command through without question.

2. `.bin/` symlinks are created for all packages, trusted or not. Blocking a package's own lifecycle scripts does nothing to stop its `bin` entries from landing in the shared `.bin/` directory.

3. PATH construction in `src/install/PackageManager/PackageManagerLifecycle.rs` prepends `node_modules/.bin` for everyone. Every package that runs scripts sees every other package's bin entries.

4. Bun keeps a [default-trusted list](https://github.com/oven-sh/bun/blob/main/src/install/default-trusted-dependencies.txt) of packages whose lifecycle scripts run automatically without `--trust`. An attacker can depend on any of them for a self-contained trigger. The victim never needs to do anything.

> [!NOTE]
> The `bin` field is the only manifest field that can put code into the execution environment without triggering the trust system. `scripts`, `exports`, `dependencies` are all correctly gated. The entire `trustedDependencies` mechanism stands or falls on this one unchecked field.

A package.json like this is accepted by Bun:

```json
{
  "name": "evil-pkg",
  "version": "^1.0.0",
  "bin": {
    "node": "./shim.js"
  },
  "dependencies": {
    "protoc-gen-grpc-web": ">=1.0.0"
  }
}
```

`evil-pkg` has zero scripts. The trust system has nothing to block. But `protoc-gen-grpc-web` is default-trusted. Its `postinstall: "node ./post-install.js"` runs automatically. That `node` call hits the poisoned `.bin/node` symlink.

---

## Proof of Concept

> [!NOTE]
> Tested on Bun v1.3.14, Linux x86_64. Works the same on macOS and Windows 11.
> The PoC writes to `/tmp/.bun-npm-pwned` to prove code ran. Nothing destructive.

### Steps to reproduce

```sh
# This will remove cache of bun, not dangerous but a headsup.
rm -rf ~/.bun/install/cache && mkdir -p ~/test-dir && cd ~/test-dir && bun i evil-pkg && cat /tmp/.bun-npm-pwned
```

### Result

```text
bun add v1.3.14 (0d9b296a)

installed evil-pkg@1.0.5 with binaries:
 - node

137 packages installed [2.27s]
PWNED by evil-pkg@1.0.5 - self-triggering PATH poisoning via default-trusted protoc-gen-grpc-web
```

---

## Impact

> [!WARNING]
> The payload runs with the victim's full user privileges during `bun install`. It can:
> - Read `.env`, SSH keys, `.npmrc` tokens, cloud credentials
> - Write to shell startup files (`.bashrc`, `.zshrc`), Git hooks, desktop autostart entries
> - Delete files, stop services, wipe the project directory
> - Exfiltrate source code, database dumps, CI/CD secrets
> - Install persistence (cron, systemd user units, launchd agents)

The trust system provides zero protection. A single untrusted dependency (with no scripts of its own) poisons PATH for every trusted package that runs scripts during install.

### Who gets hit the hardest

- **CI/CD pipelines** that run `bun install` in automated build/test environments. These never run the application. They only install dependencies. `trustedDependencies` was supposed to make this safe.
- **Security scanners** and dependency auditors that install packages to look at them
- **Automated dependency updaters** (Renovate, Dependabot, etc.) that run `bun install` to check for new versions
- **Monorepo tooling** that installs shared workspace dependencies

In every one of these, the tool runs `bun install`, never touches the application code, and expects to be safe. The `bin` PATH poisoning breaks that expectation.

### Common shadow targets

| Shadow Binary | Triggered By |
|---------------|--------------|
| `node` | Almost every postinstall script |
| `sh` | Shell commands in build pipelines |
| `make` | node-gyp for native addons |
| `gcc`, `g++` | Native module compilation |
| `python` | node-gyp config scripts |
| `curl`, `wget` | Binary downloads in postinstall |
| `git` | CI scripts, pre-commit hooks |

One malicious package can shadow all of them at once:

```json
{
  "bin": {
    "node": "./p",
    "sh": "./p",
    "make": "./p",
    "gcc": "./p",
    "curl": "./p"
  },
  "dependencies": {
    "protoc-gen-grpc-web": ">=1.0.0"
  }
}
```

### How this plays out in the real world

Any package on the npm registry (or any scoped registry) can carry a malicious `bin` field without triggering any registry-side checks. There is no npm rule that stops `"bin": {"node": "./x"}`. It is valid syntax and is actually used for real tool aliasing (like `"bin": {"make": "./build.js"}` in build-tool packages).

- Publish a package with a normal looking name
- Depend on a popular default-trusted build tool
- Ship a `bin` field that shadows `node` (or `sh`, `make`, etc.)
- Get code execution on every `bun install` with no prompts, no flags, no consent


> btw while uploading the evil-pkg on npm, NPM did mentioned it stripped our something from node, but it stipped nothing, don't know what it was.

---

## Maintainer Response

The Bun maintainer reviewed this and declined to treat it as a security issue:

> Thanks for the writeup, but this isn't a vulnerability. The report rests on a misunderstanding of what trustedDependencies is.
>
> trustedDependencies gates lifecycle scripts. That's it. It has nothing to do with bin linking and has never claimed to. Bin links are symlinks — creating one is not code execution. The report treats "the attacker's package does not need to be trusted" as a bypass, but that's just a correct description of a mechanism that was never in scope for trust in the first place.
>
> Every package manager creates node_modules/.bin entries for every dependency and puts .bin on PATH for lifecycle scripts. npm, pnpm, yarn — all of them. On npm your evil-pkg doesn't need the shim or the protoc-gen-grpc-web dependency at all; its own postinstall just runs. Bun is more restrictive here, not less.
>
> And the premise is that the victim installs the attacker's package. At that point the attacker controls main — require("evil-pkg") is RCE with no symlinks involved. The PATH shim is a strictly more convoluted path to code you already agreed to run. Nothing about the CVSS scoring (AV:N, PR:N, Critical) reflects that.

> [!NOTE]
> **My take**: The maintainer is right that `trustedDependencies` only gates lifecycle scripts, and `bin` was never in scope for the trust system. I just think it should be. The whole reason `trustedDependencies` exists is to make `bun install` safe. If untrusted code can run during install through the `bin` field (a path the trust system never considered), then the trust system has a gap. Whether you call that a vulnerability or a design flaw, the result is the same: `trustedDependencies` does not fully deliver on its promise.

---

## My analysis

`trustedDependencies` was built to answer: "should this package's lifecycle scripts be allowed to run?" It never asked: "should this package be allowed to put its own executables on the PATH of trusted packages?"

The `bin` field writes into a shared execution namespace that every package's scripts inherit. Treating it as something that does not need trust checks is the core problem.

> [!IMPORTANT]
> fix is to make sure `node_modules/.bin` entries from untrusted packages are not visible on the PATH of trusted packages' lifecycle scripts. The trust boundary needs to cover the `bin` field too.

---

*BunnyHijack shows that `trustedDependencies` blocks one attack (malicious lifecycle scripts) but leaves an equally useful attack (malicious `bin` entries) wide open. The whole promise of `trustedDependencies` (that `bun install` is safe even with untrusted packages) is broken by design. Until the trust boundary covers the `bin` field, the trust system does not do what it says it does.*
