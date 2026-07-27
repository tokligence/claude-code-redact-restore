# redmem — development guide

Claude Code hooks: a secret shield, session memory, an image compressor, an
autopilot loop, and a set of guards. Everything runs as a short-lived
subprocess spawned per tool call, which shapes almost every constraint below.

Read `docs/design/architecture.md` for the full specification. This file is
what you need before touching the code.

---

## The one that will bite you first: the interpreter

**`python3` on `PATH` is not necessarily the interpreter with your packages.**

A hook process does not source your shell rc. So the `python3` that resolves
correctly when you type it can resolve to something else entirely when Claude
Code spawns the hook. An `alias python3=...` is worse than useless here: an
alias exists only in interactive shells, so it hides the split rather than
fixing it.

On 2026-07-27 this destroyed a 235-entry encrypted vault twice in one session.
The machine had two brew pythons; the one holding the linked `python3` had no
`cryptography`, so the shield could not decrypt its own mapping, treated it as
empty, and truncated it. Every check run by hand said the right interpreter.

Consequences for you:

- **Run tests with an interpreter that has `cryptography`**, not with whatever
  `python3` resolves to. Verify before you trust it:
  ```
  <your python3> -c 'import sys, cryptography; print(sys.executable)'
  ```
- `install.sh` resolves an interpreter, requires `import cryptography`, and
  writes its **absolute path** into `settings.json`. It refuses to install if
  none qualifies. Do not "simplify" that back to `python3`.
- **Claude Code caches hook commands at session start.** Editing
  `settings.json` does not affect the running session. After `install.sh`,
  restart Claude Code or you will be testing the old configuration and drawing
  confident, wrong conclusions.

---

## Running the tests

```
<python-with-cryptography> -m pytest -q          # full suite, ~90s
<python-with-cryptography> -m pytest test_vault_integrity.py -q
```

Roughly 800 tests. They are hermetic and must stay that way — see below.

Several suites accept `REDMEM_HOOK_UNDER_TEST=<path>` so the same assertions
can be run against an older copy of the hook. That is how "red before the fix"
gets demonstrated without hand-editing source:

```
git show HEAD~1:hooks/redact-restore.py > /tmp/scratch/old-hook.py
REDMEM_HOOK_UNDER_TEST=/tmp/scratch/old-hook.py python3 -m pytest test_vault_integrity.py -q
```

Stage that copy somewhere clean, **not** in `/tmp` directly: `/tmp` lands on
`sys.path[0]` for a script run from there, and a stray `/tmp/types.py` will
shadow the stdlib and stop the hook from even starting.

---

## Architecture: the dispatcher chain

`settings.json` points every hook event at `hooks/redmem_dispatcher.py`, which
routes internally. One matcher per event keeps the settings file small.

The **PreToolUse** order, and it matters:

```
run_shield()            → computes shield_result (may carry updatedInput)
  ↓ if the shield DENIED, emit and stop
secret_ops_guard        → may respond and stop
image-original sentinel → may respond and stop
git_guard               → may respond and stop
autopilot bash guard    → may respond and stop
deploy_config_guard     → may respond and stop
image compressor        → may respond and stop
  ↓
print(shield_result)    ← the shield's own result is emitted LAST
```

**The hazard, stated plainly: the shield runs first but its result is emitted
last, and the chain stops at the first handler that responds.** So any guard
that answers in between silently discards the shield's `updatedInput`. That is
not theoretical — it is exactly how `Write`/`Edit` could write
placeholder-bearing content back to disk: `deploy_config_guard` returns `ask`,
the user approves, and the original tool input (still containing placeholders)
is what executes.

If you add a handler:

- Know where it sits in that chain and what it pre-empts.
- If it only inspects and never rewrites `tool_input`, prefer placing it before
  handlers that do rewrite.
- Add a dispatcher-level test. A unit test on your function passes whether or
  not the function is ever *called* — `deploy_config_guard` shipped with 64
  passing tests while being absent from every real installation, and while
  `install.sh`'s matcher routed neither `MultiEdit` nor `NotebookEdit` to it.

---

## The shield's data model

- **Mapping**: `~/.claude/.redact-mapping.json`, Fernet-encrypted with a key
  derived from `~/.claude/.redact-hmac-key`. Placeholders are deterministic —
  `{{NAME_hash8}}` where the digest is an HMAC of the secret — so the same
  secret always yields the same placeholder, on any machine with that key.
- **Backups**: `/tmp/.claude-backup-<session_id>/<path-hash>.bak`. Session-keyed,
  which is why a PostToolUse arriving under a different session id used to find
  nothing and leave a file redacted forever.
- **Failure log**: `~/.claude/vault/restore-errors.log`, one JSON line per
  failure, size-capped, secret-scrubbed. Paths and placeholder names ARE
  recorded, deliberately: an alarm you cannot act on is the same as no alarm.

A placeholder in a file is only meaningful while the mapping holds its entry.
Lose the entry and the file is corrupted permanently, with no way to tell what
used to be there. **That is the asymmetry the whole design turns on.**

---

## Failure philosophy — fail-open, except when the failure destroys data

The general rule is **fail-open**: a hook bug must never block someone's edit.
Every handler wraps itself and returns `None` on any unexpected shape.

But fail-open was written for handlers that might *block* something. It is the
wrong posture for one that might *delete* something, and conflating the two is
how the vault incident happened. The rules that came out of it:

1. **An unreadable vault is not an empty vault.** `save_mapping` opens with
   truncating semantics, so "load failed → empty mapping → save" replaces
   everything. A mapping that could not be read is marked, and never written
   over.
2. **If you cannot persist, do not redact.** Minting a placeholder while unable
   to save the mapping writes a marker nothing can ever restore. Losing the
   shield for one invocation is recoverable; corrupting a file is not.
3. **If you cannot encrypt, do not write.** Plaintext persistence is gone. A
   tool whose job is hiding secrets must never put them on disk in the clear
   while reporting success.
4. **Every degraded path leaves a trace** — a durable log line *and* an in-band
   PostToolUse warning. A shield that quietly stops working looks exactly like
   one that is working; that is why nobody noticed for an unknown period.

When you add a failure branch, ask which of "blocked" and "destroyed" it can
cause, and pick the posture accordingly.

---

## Test discipline (hard rules)

- **Never touch the real `HOME`.** Set `env["HOME"]` and `env["TMPDIR"]` to
  `tmp_path` subdirectories for every hook subprocess. `BACKUP_DIR` derives from
  `tempfile.gettempdir()`, so a shared `TMPDIR` collides with live backups.
  This is not hypothetical: a test that drove the real dispatcher with the real
  `HOME` rewrote this repository's own README on every full-suite run, and
  taught the developer's real mapping a documentation example.
- **Never touch repository files.** A `Read` PreToolUse redacts its target on
  disk and relies on a matching PostToolUse to put it back — a test that sends
  only PreToolUse leaves the file redacted. `test_deploy_config_guard_e2e.py`
  has a `_run()` guard that raises if any payload path resolves inside the repo;
  copy that pattern.
- **Fixtures must be synthetic.** A realistic-looking secret in a test file
  becomes a *live* one: reading the file teaches the real mapping, which makes
  the placeholder on the next line resolvable, which means any Bash command
  naming that file rewrites it with the real value — in a tracked file of a
  public repo. See the note at the top of `test_placeholder_bake_relative.py`.
- **Prove red before green.** Every fix here has a test that fails against the
  previous hook. This is not ceremony: a fail-open branch with no test is
  indistinguishable from a working one, and one of these fixes was written with
  a `NameError` in it that silently disabled *all* restore protection — caught
  only because the regression test came first.
- **Watch for tests that pass for the wrong reason.** One test of the "spaced
  interpreter path" case used a symlink and passed against the unfixed code,
  because the installer normalises through `sys.executable`, which resolves the
  symlink and drops the space. If an assertion depends on a precondition,
  assert the precondition too.

---

## install.sh / uninstall.sh

They must stay symmetrical: **anything install writes, uninstall removes.** The
suite enforces this, and it works — `test_uninstall.py` went red the moment
install started creating a file it did not know about.

Entry matching in both scripts is by **script path anchored on a real
`.claude/` segment**, not by whole command string. The interpreter prefix is
machine-specific, so exact comparison de-duplicates only on the machine that
wrote the entries: re-installs append duplicates, and uninstalls leave orphan
entries pointing at deleted files — which makes every tool call fail to spawn,
worse than either failure alone.

After changing the installer, run it into an isolated `HOME` and then **run the
installed dispatcher** with a real event. Asserting a file list only restates
the list.

---

## Review

Code changes go through Codex adversarial review until findings converge
(`SHIP`). Verify each finding against the code before accepting it — Codex is
adversarial, not authoritative, and it produces both real defects and confident
non-problems. Rejecting a finding is fine; rejecting one without checking is
not. Record the dispositions in the commit message, including what you rejected
and why.

```bash
cat /tmp/scratch/prompt.txt | codex exec --model gpt-5.5 \
  --sandbox read-only --skip-git-repo-check --ephemeral \
  -C /Users/you/redmem -o /tmp/scratch/final.md > /tmp/scratch/stream.out 2>&1 &
```

Prompts go in via **stdin from a file** (heredocs hang), always with `-o` (the
clean final message; stdout is reasoning chatter), and never piped to `tail`
(it buffers until EOF, so you see nothing while it runs). Self-contained
prompts work best: inline the code under review and tell it not to read files.
If the output is only the echoed prompt, the run died — check the network, then
retry before concluding anything about prompt size.

---

## Conventions

- **Commit messages explain the failure and the reasoning**, not the change —
  read `git log` before writing one. What broke, why it was reachable, what the
  fix guarantees, what was rejected. They are the durable record of why the code
  looks the way it does.
- **Update `CHANGELOG.md`** in the same commit. Entries carry the mechanism and
  the test count, not a one-liner.
- No `Co-Authored-By`.
- No `rm` — `mv` to `/tmp/discarded-<timestamp>-<name>` if something must go.
- Never print a real secret value, and never inspect the developer's real
  mapping. Debug with counts and booleans.

## Layout

```
hooks/
  redmem_dispatcher.py   routing for every hook event
  redact-restore.py      the shield (largest module; mapping, redact, restore)
  patterns.py            secret patterns; custom-patterns.py extends per-repo
  deploy_config_guard.py git_guard.py secret_ops_guard.py
  image_compressor.py  cheatsheet.py  redmem_catchup.py
  autopilot/  memory/  guard/
install.sh  uninstall.sh
test_*.py                ~800 tests, hermetic, no network
docs/design/architecture.md
```

## 改动流程：worktree fork → squash merge（硬规则，全部 tokligence 仓）

**任何改动都先开 worktree，不在主工作树里直接改**，然后 squash 合回主集成分支。

```bash
git worktree add .claude/worktrees/<name> -b <branch> <base>
# 在 worktree 里改、跑测试、提交
git merge --squash <branch> && git commit      # 主工作树里合，一个 feature 一个 commit
git worktree remove .claude/worktrees/<name> && git branch -D <branch> && git worktree prune
```

### 为什么不只是"别切分支"

以前的规则是"绝不在共享仓里 `git checkout` / `git switch`"，防的是**分支冲突**。
但真正踩过的坑是**文件冲突**：主工作树里跑任何会写文件的命令 —— `npm ci`、代码生成器
（如 `npm run rankings:sync` 会重写 `src/lib/model-rankings-auto.ts`）、`git rebase`
的 autostash —— 都会动到别人/别的 session 正在编辑的文件，而且不留痕迹。

所以边界不是"有没有切分支"，是**有没有写文件**。写文件就进 worktree。

### 收尾（同样是硬规则）

合并后立刻清理，否则 worktree 会累积（本仓曾积到 31 个）：

```bash
git worktree list                    # 定期审计
git -C <path> log --oneline <base>..HEAD    # 空 = 已合并
git -C <path> status --porcelain            # 空 = 无未提交改动
# 两个都空 → 安全删除
```

**主工作树必须留在主集成分支上**，绝不留在旧 feature 分支 —— 下一个 session 在这个仓
启动会读到过时代码并据此决策。

### 唯一例外：promote 不 squash

`staging → main` 的 promote 是 fast-forward / merge commit，**不能 squash**。
squash 会切断祖先链，`git log origin/main..origin/staging` 从此失真，看不出线上到底发布了什么。
