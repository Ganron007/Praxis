---
name: praxis-hooks
description: Install praxis as real-time Claude Code hooks — blocks secrets and dangerous commands before they land on disk. Use when the user wants automatic security scanning on every file write or bash command.
argument-hint: "[install|remove|status]"
---

# Praxis — Claude Code Hooks

You are installing praxis as real-time security hooks into Claude Code. Once installed, praxis will:

- **Block** `Write` / `Edit` / `MultiEdit` calls that contain critical secrets (API keys, tokens, private keys) **before** they are written to disk
- **Block** `Bash` calls matching dangerous patterns (curl piped to shell, credential exfiltration)
- **Scan** every file after it is written and inject advisory findings directly into this conversation

## Step 1: Determine the action

If `$ARGUMENTS` is `remove`: run the remove command below.
If `$ARGUMENTS` is `status`: run the status command below.
Otherwise (default or `install`): run the install command.

## Step 2: Run the command

**Install (default):**
```bash
npx praxis@latest hooks install
```

**Remove:**
```bash
npx praxis@latest hooks remove
```

**Status check:**
```bash
npx praxis@latest hooks status
```

## Step 3: Report the result

**On install success:**
- Confirm that two hooks are now registered in `~/.claude/settings.json`
- Explain what each hook does:
  - **PreToolUse** (on Write / Edit / MultiEdit / Bash): blocks critical secrets and dangerous commands in real time
  - **PostToolUse** (on Write / Edit / MultiEdit): scans the written file and reports findings in context
- Tell the user that **no restart is needed** — hooks take effect immediately

**On remove success:**
- Confirm the hooks were removed from `~/.claude/settings.json`

**On status:**
- Report which hooks are installed (✔) and which are missing (✗)
- If any are missing, offer to run `install`

**On error:**
- If the command fails, check whether Node.js 18+ is available: `node --version`
- If hook scripts are missing, suggest reinstalling: `npm install -g praxis`

## Notes

- Hooks are stored in `~/.claude/settings.json` (global) so they apply to all Claude Code projects
- The hooks are non-invasive: they only read file content and run patterns locally — no data is sent externally
- PostToolUse never blocks, it only informs
- To see what was installed: `cat ~/.claude/settings.json`
