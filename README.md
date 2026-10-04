# Xzy Security Bot

Anti-nuke / security bot for Discord. Python 3.11+, discord.py 2.6+, SQLite, `.env`.

## Features
- **Audit-Log detection (real time):** mass channel/role deletion, mass channel/role/webhook **creation** (spam floods are auto-deleted), mass bans/kicks, webhook deletion, server-name changes, unauthorized bot additions. Every bot addition is logged (authorised ones in green).
- **Configurable punishment:** ban / kick / timeout, with expiry (temporary bans are auto-unbanned, even across restarts).
- **Whitelist** and **Security Bot Admins**.
- **Auto-restore:** channels (permissions, categories, topics...), roles, server name, mass-ban victims; server icon via `/autorestore restore_now`. Best-effort **message backup/replay** into restored channels.
- **Exact logs:** `🚨 Bot Alert` and `⛔ Unauthorised Command` embeds.
- **Unauthorised command guard:** blocks `!commands` you choose (`/addunauth`) for non-admins; also logs non-admins trying to use the slash commands.
- Everything persisted in SQLite (WAL mode).

## Setup (Ubuntu + venv)
```bash
unzip discord-security-bot.zip && cd discord-security-bot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && nano .env      # set DISCORD_TOKEN
python bot.py
```

### Developer Portal
1. Create an application → **Bot** tab → copy the token into `.env`.
2. Enable **Message Content Intent** (privileged). If you don't want it, set `ENABLE_MESSAGE_CONTENT=false` (message backup and the `!` guard are then off).
3. Invite with scopes `bot applications.commands` and permissions integer **`1100317027510`**
   (View Channels, Send Messages, Manage Messages, Embed Links, Read Message History, Manage Channels, Manage Roles, Manage Server, Kick, Ban, Timeout, View Audit Log, Manage Webhooks) — or simply Administrator.
4. **Drag the bot's role to the top** of the role list. It can only punish, restore and reorder roles *below* its own role.

### Run as a service
```ini
# /etc/systemd/system/xzy-security.service
[Unit]
Description=Xzy Security Bot
After=network-online.target
[Service]
WorkingDirectory=/opt/discord-security-bot
ExecStart=/opt/discord-security-bot/venv/bin/python bot.py
Restart=always
RestartSec=5
User=botuser
[Install]
WantedBy=multi-user.target
```
`sudo systemctl enable --now xzy-security`

## Commands
| Command | Who | Purpose |
|---|---|---|
| `/help` | everyone | Command overview |
| `/adminadd` `/adminremove` | server owner | Manage Security Bot Admins |
| `/adminlist` | admins | List admins |
| `/setlog` | admins | Channel for Bot Alert / Unauthorised Command logs |
| `/antinuke` | admins | Enable / disable / status |
| `/autorestore` | admins | Enable / disable / status / **restore now** |
| `/whitelist` | admins | Add / remove / list exempt users and bots |
| `/addpunisment` | admins | `ban` / `kick` / `timeout` + duration (`30m`, `12h`, `7d`; ban `0` = permanent) |
| `/addunauth` `/removeunauth` `/unauthlist` | admins | Manage blocked `!commands` |
| `/threshold` | admins | Limit + window (seconds) per action; omit to view |
| `/security` | admins | Status, recent incidents, refresh snapshot |

Non-admins who try an admin command are blocked and logged as *Unauthorised Command*.

## How it works
- **Exempt from punishment:** server owner, the bot itself, whitelisted IDs. Security Bot Admins are **not** exempt (a compromised admin is exactly what anti-nuke is for) — whitelist trusted admins.
- **Bot additions:** only the owner or whitelisted users may add bots (or whitelist the bot's ID). Others: bot is banned and the adder punished.
- **Server rename:** by a non-exempt user → reverted immediately and the user punished.
- **Snapshots** are refreshed on changes and every ~15 min. After a violation they are **paused for 10 minutes** so an attacker's changes can't overwrite the trusted state. Deleted items are flagged, never erased (kept 7 days).
- Defaults: 3 actions / 60 s for deletions, bans, kicks; 5 / 10 s for channel & role creation; 3 / 10 s for webhook creation. `/threshold` accepts a window from 1 s; `limit:1` punishes on the very first action.

## Limitations (Discord-imposed)
- Role **members** are not restored; webhooks cannot be restored (tokens are lost).
- Message restore is best-effort: only messages seen while the bot was online (last `MESSAGE_BACKUP_LIMIT` per channel), re-posted by webhook with the original author name/avatar. Attachments are re-linked, not re-uploaded.
- The bot cannot act on users/roles above its own role, or timeout Administrators (it then strips dangerous roles as a fallback).
- Message backup stores message text in your local SQLite file — mention this in your server rules/privacy notice, or disable with `ENABLE_MESSAGE_BACKUP=false`.

## Troubleshooting (no logs / no protection)
Run `/security` — it shows missing permissions, how many Audit Log events the bot has received, and roles above the bot.
1. **No log channel:** run `/setlog` (alerts otherwise only DM the server owner).
2. **"Audit events: none":** the bot lacks **View Audit Log**, or was invited without `Guild Moderation` access. Re-invite with the permissions integer above.
3. **Owner/whitelisted actions are never punished.** Test with a non-owner, non-whitelisted account or bot.
4. **Role hierarchy:** the bot's role must be above the attacker's role, otherwise punishment fails (the alert is still sent).
5. Watch `data/xzy_security.log` / console for `missing permissions` warnings at startup.

Files: `data/xzy_security.db` (database), `data/xzy_security.log` (rotating log), `data/icons/` (icon snapshots).
