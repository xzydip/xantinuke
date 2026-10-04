#!/usr/bin/env python3
"""
Xzy Security Bot
================
Anti-nuke / security bot for Discord (discord.py 2.6+, SQLite, .env).

Detects (via real-time Audit Log events):
  * mass channel deletion        * mass role deletion
  * mass bans                    * webhook deletion
  * server-name changes          * unauthorized bot additions

Punishes (ban / kick / timeout, with optional expiry), logs exact
"Bot Alert" and "Unauthorised Command" embeds, keeps SQLite-persisted
snapshots (server name/icon, channels, roles) and a best-effort message
backup so deleted channels/roles can be restored automatically.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

import discord
from discord import app_commands
from discord.ext import tasks
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BOT_NAME = "Xzy Security Bot"
BASE_DIR = Path(__file__).resolve().parent


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(minimum, value)


def env_id_set(name: str) -> set[int]:
    out: set[int] = set()
    for part in re.split(r"[,\s]+", os.getenv(name, "")):
        if part.strip().isdigit():
            out.add(int(part.strip()))
    return out


DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data"))).expanduser()
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "xzy_security.db"))).expanduser()
ICON_DIR = DATA_DIR / "icons"
LOG_FILE = DATA_DIR / "xzy_security.log"

OWNER_IDS = env_id_set("OWNER_IDS")
DEV_GUILD_ID = env_int("DEV_GUILD_ID", 0)
ENABLE_MESSAGE_CONTENT = env_bool("ENABLE_MESSAGE_CONTENT", True)
ENABLE_MESSAGE_BACKUP = env_bool("ENABLE_MESSAGE_BACKUP", True) and ENABLE_MESSAGE_CONTENT
MESSAGE_BACKUP_LIMIT = env_int("MESSAGE_BACKUP_LIMIT", 100, 10)  # per channel
MESSAGE_RETENTION_DAYS = env_int("MESSAGE_RETENTION_DAYS", 7, 1)
MESSAGE_RESTORE_LIMIT = env_int("MESSAGE_RESTORE_LIMIT", 50, 0)  # replayed per channel
RESTORE_LOOKBACK_HOURS = env_int("RESTORE_LOOKBACK_HOURS", 24, 1)
UNAUTH_PREFIX = os.getenv("UNAUTH_PREFIX", "!").strip() or "!"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

QUARANTINE_SECONDS = 600     # snapshots paused this long after a violation
HANDLED_TTL = 300            # a punished executor is "known bad" this long
MAX_TIMEOUT_SECONDS = 28 * 86400
SNAPSHOT_KEEP_DELETED_DAYS = 7
INCIDENT_KEEP_DAYS = 90

DEFAULT_THRESHOLDS: dict[str, tuple[int, int]] = {
    "channel_delete": (3, 60),
    "role_delete": (3, 60),
    "member_ban": (3, 60),
    "webhook_delete": (3, 60),
    "member_kick": (3, 60),
    "channel_create": (5, 10),
    "role_create": (5, 10),
    "webhook_create": (3, 10),
}
KIND_LABELS = {
    "channel_delete": "Mass Channel Deletion",
    "role_delete": "Mass Role Deletion",
    "member_ban": "Mass Ban",
    "webhook_delete": "Webhook Deletion",
    "member_kick": "Mass Kick",
    "channel_create": "Mass Channel Creation",
    "role_create": "Mass Role Creation",
    "webhook_create": "Mass Webhook Creation",
    "bot_add": "Unauthorized Bot Addition",
    "server_name": "Server Name Change",
}
IMMEDIATE_KINDS = {"bot_add", "server_name"}
TRACKED_ACTIONS = {
    discord.AuditLogAction.channel_delete: "channel_delete",
    discord.AuditLogAction.role_delete: "role_delete",
    discord.AuditLogAction.ban: "member_ban",
    discord.AuditLogAction.webhook_delete: "webhook_delete",
    discord.AuditLogAction.kick: "member_kick",
    discord.AuditLogAction.channel_create: "channel_create",
    discord.AuditLogAction.role_create: "role_create",
    discord.AuditLogAction.webhook_create: "webhook_create",
}
PUBLIC_COMMANDS = {"help"}
OWNER_ONLY_COMMANDS = {"adminadd", "adminremove"}

REQUIRED_PERMS = {
    "view_audit_log": "View Audit Log",
    "ban_members": "Ban Members",
    "kick_members": "Kick Members",
    "moderate_members": "Timeout Members",
    "manage_channels": "Manage Channels",
    "manage_roles": "Manage Roles",
    "manage_guild": "Manage Server",
    "manage_webhooks": "Manage Webhooks",
    "manage_messages": "Manage Messages",
}
DANGEROUS_PERMS = (
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members", "moderate_members",
)

COLOR_RED = 0xE74C3C
COLOR_ORANGE = 0xE67E22
COLOR_GREEN = 0x2ECC71
COLOR_BLUE = 0x3498DB

log = logging.getLogger("xzy")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def setup_logging() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    try:
        fileh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except OSError as exc:  # read-only FS etc.
        print(f"Could not open log file: {exc}", file=sys.stderr)
    logging.getLogger("discord.http").setLevel(logging.WARNING)


def clip(text: Any, limit: int = 1000) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


_DUR_FULL = re.compile(r"^(?:\d+[smhdw])+$")
_DUR_PART = re.compile(r"(\d+)([smhdw])")
_DUR_MULT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> Optional[int]:
    """'1h30m' -> 5400. '0'/'perm' -> 0 (permanent). Invalid -> None."""
    t = re.sub(r"\s+", "", text.strip().lower())
    if t in {"0", "perm", "permanent", "forever", "none"}:
        return 0
    if not _DUR_FULL.match(t):
        return None
    return sum(int(n) * _DUR_MULT[u] for n, u in _DUR_PART.findall(t))


def fmt_duration(seconds: int) -> str:
    if seconds <= 0:
        return "permanent"
    parts = []
    for label, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            parts.append(f"{seconds // size}{label}")
            seconds %= size
    return " ".join(parts)


def normalise_command(text: str) -> Optional[str]:
    t = text.strip().lower()
    if t.startswith(UNAUTH_PREFIX):
        t = t[len(UNAUTH_PREFIX):]
    t = t.strip()
    return t if re.fullmatch(r"[a-z0-9_\-]{1,32}", t) else None


def mention(user_id: int) -> str:
    return f"<@{user_id}>"


# --------------------------------------------------------------------------- #
# Database (SQLite, thread-safe; used through asyncio.to_thread)
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id            INTEGER PRIMARY KEY,
    alert_channel_id    INTEGER,
    unauth_channel_id   INTEGER,
    antinuke_enabled    INTEGER NOT NULL DEFAULT 1,
    autorestore_enabled INTEGER NOT NULL DEFAULT 1,
    punishment          TEXT    NOT NULL DEFAULT 'ban',
    punishment_duration INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS admins (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    added_by INTEGER, added_at INTEGER,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS whitelist (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    added_by INTEGER, added_at INTEGER,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS unauth_commands (
    guild_id INTEGER NOT NULL, command TEXT NOT NULL,
    added_by INTEGER, added_at INTEGER,
    PRIMARY KEY (guild_id, command)
);
CREATE TABLE IF NOT EXISTS thresholds (
    guild_id INTEGER NOT NULL, action TEXT NOT NULL,
    limit_count INTEGER NOT NULL, window_seconds INTEGER NOT NULL,
    PRIMARY KEY (guild_id, action)
);
CREATE TABLE IF NOT EXISTS temp_bans (
    guild_id INTEGER NOT NULL, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id INTEGER NOT NULL, created_at INTEGER NOT NULL,
    kind TEXT NOT NULL, executor_id INTEGER, executor_name TEXT,
    details TEXT, punishment TEXT, restore TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_guild ON incidents (guild_id, created_at);
CREATE TABLE IF NOT EXISTS snap_guild (
    guild_id INTEGER PRIMARY KEY, name TEXT, icon_hash TEXT, icon_path TEXT, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS snap_channels (
    guild_id INTEGER NOT NULL, channel_id INTEGER NOT NULL, name TEXT,
    data TEXT NOT NULL, deleted_at INTEGER, updated_at INTEGER,
    PRIMARY KEY (guild_id, channel_id)
);
CREATE TABLE IF NOT EXISTS snap_roles (
    guild_id INTEGER NOT NULL, role_id INTEGER NOT NULL, name TEXT,
    data TEXT NOT NULL, deleted_at INTEGER, updated_at INTEGER,
    PRIMARY KEY (guild_id, role_id)
);
CREATE TABLE IF NOT EXISTS message_backup (
    message_id INTEGER PRIMARY KEY, guild_id INTEGER NOT NULL, channel_id INTEGER NOT NULL,
    author_id INTEGER, author_name TEXT, author_avatar TEXT,
    content TEXT, attachments TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msgbackup_channel ON message_backup (channel_id, message_id);
"""

CFG_COLUMNS = {
    "alert_channel_id", "unauth_channel_id", "antinuke_enabled",
    "autorestore_enabled", "punishment", "punishment_duration",
}


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self.lock:
            try:
                cur = self.conn.execute(sql, params)
                self.conn.commit()
                return cur.lastrowid or 0
            except Exception:
                self.conn.rollback()
                raise

    def fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchone()

    def upsert_settings(self, guild_id: int, values: dict[str, Any]) -> None:
        cols = [c for c in values if c in CFG_COLUMNS]
        if not cols:
            return
        col_sql = ", ".join(cols)
        ph = ", ".join("?" for _ in cols)
        upd = ", ".join(f"{c}=excluded.{c}" for c in cols)
        self.execute(
            f"INSERT INTO guild_settings (guild_id, {col_sql}) VALUES (?, {ph}) "
            f"ON CONFLICT(guild_id) DO UPDATE SET {upd}",
            (guild_id, *[values[c] for c in cols]),
        )

    def write_snapshot(self, guild_id: int, name: str, icon_hash: Optional[str],
                       icon_path: Optional[str], channels: list[tuple],
                       roles: list[tuple], now: int) -> None:
        with self.lock:
            c = self.conn
            try:
                c.execute(
                    "INSERT INTO snap_guild (guild_id, name, icon_hash, icon_path, updated_at) "
                    "VALUES (?,?,?,?,?) ON CONFLICT(guild_id) DO UPDATE SET name=excluded.name, "
                    "icon_hash=excluded.icon_hash, icon_path=excluded.icon_path, updated_at=excluded.updated_at",
                    (guild_id, name, icon_hash, icon_path, now),
                )
                for table, col, rows in (("snap_channels", "channel_id", channels),
                                         ("snap_roles", "role_id", roles)):
                    c.executemany(
                        f"INSERT INTO {table} (guild_id, {col}, name, data, deleted_at, updated_at) "
                        f"VALUES (?,?,?,?,NULL,?) ON CONFLICT(guild_id, {col}) DO UPDATE SET "
                        "name=excluded.name, data=excluded.data, deleted_at=NULL, updated_at=excluded.updated_at",
                        [(guild_id, rid, nm, data, now) for rid, nm, data in rows],
                    )
                    # Entities missing from the live guild are flagged deleted, never erased.
                    ids = [r[0] for r in rows]
                    if ids:
                        ph = ",".join("?" for _ in ids)
                        c.execute(
                            f"UPDATE {table} SET deleted_at=? WHERE guild_id=? AND deleted_at IS NULL "
                            f"AND {col} NOT IN ({ph})", (now, guild_id, *ids))
                    else:
                        c.execute(f"UPDATE {table} SET deleted_at=? WHERE guild_id=? AND deleted_at IS NULL",
                                  (now, guild_id))
                c.commit()
            except Exception:
                c.rollback()
                raise

    def upsert_channel(self, guild_id: int, channel_id: int, name: str, data: str, now: int) -> None:
        self.execute(
            "INSERT INTO snap_channels (guild_id, channel_id, name, data, deleted_at, updated_at) VALUES (?,?,?,?,NULL,?) "
            "ON CONFLICT(guild_id, channel_id) DO UPDATE SET name=excluded.name, data=excluded.data, "
            "deleted_at=NULL, updated_at=excluded.updated_at", (guild_id, channel_id, name, data, now))

    def flush_messages(self, rows: list[tuple], deletes: list[int]) -> None:
        with self.lock:
            try:
                if rows:
                    self.conn.executemany(
                        "INSERT OR REPLACE INTO message_backup (message_id, guild_id, channel_id, author_id, "
                        "author_name, author_avatar, content, attachments, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        rows)
                if deletes:
                    self.conn.executemany("DELETE FROM message_backup WHERE message_id=?",
                                          [(d,) for d in deletes])
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def maintenance(self, per_channel: int, msg_cutoff: int, snap_cutoff: int, inc_cutoff: int) -> None:
        with self.lock:
            try:
                self.conn.execute("DELETE FROM message_backup WHERE created_at < ?", (msg_cutoff,))
                self.conn.execute(
                    "DELETE FROM message_backup WHERE message_id IN (SELECT message_id FROM ("
                    "SELECT message_id, ROW_NUMBER() OVER (PARTITION BY channel_id ORDER BY message_id DESC) AS rn "
                    "FROM message_backup) WHERE rn > ?)", (per_channel,))
                self.conn.execute("DELETE FROM snap_channels WHERE deleted_at IS NOT NULL AND deleted_at < ?", (snap_cutoff,))
                self.conn.execute("DELETE FROM snap_roles WHERE deleted_at IS NOT NULL AND deleted_at < ?", (snap_cutoff,))
                self.conn.execute("DELETE FROM incidents WHERE created_at < ?", (inc_cutoff,))
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.commit()
                self.conn.close()
            except sqlite3.Error:
                pass


# --------------------------------------------------------------------------- #
# Snapshot serialisation helpers
# --------------------------------------------------------------------------- #
def channel_data(ch: discord.abc.GuildChannel) -> Optional[dict]:
    overwrites = []
    for target, ow in ch.overwrites.items():
        allow, deny = ow.pair()
        overwrites.append({
            "id": target.id,
            "type": "role" if isinstance(target, discord.Role) else "member",
            "allow": allow.value, "deny": deny.value,
        })
    data: dict[str, Any] = {
        "id": ch.id, "name": ch.name, "type": ch.type.value, "position": ch.position,
        "category_id": ch.category_id, "overwrites": overwrites,
    }
    if isinstance(ch, discord.StageChannel):
        data.update(bitrate=ch.bitrate, user_limit=ch.user_limit)
    elif isinstance(ch, discord.VoiceChannel):
        data.update(bitrate=ch.bitrate, user_limit=ch.user_limit)
    elif isinstance(ch, discord.TextChannel):
        data.update(topic=ch.topic, nsfw=ch.nsfw, slowmode=ch.slowmode_delay)
    elif isinstance(ch, discord.ForumChannel):
        data.update(topic=ch.topic, nsfw=ch.nsfw, slowmode=ch.slowmode_delay)
    elif isinstance(ch, discord.CategoryChannel):
        pass
    else:
        return None
    return data


def role_data(role: discord.Role) -> Optional[dict]:
    if role.is_default() or role.managed:
        return None
    return {
        "id": role.id, "name": role.name, "colour": role.colour.value, "hoist": role.hoist,
        "mentionable": role.mentionable, "permissions": role.permissions.value,
        "position": role.position,
    }


# --------------------------------------------------------------------------- #
# Command tree with global authorisation
# --------------------------------------------------------------------------- #
class SecurityTree(app_commands.CommandTree):
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        client = interaction.client
        if isinstance(client, XzyBot):
            return await client.authorize_interaction(interaction)
        return True

    async def on_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CheckFailure):
            return  # authorize_interaction already responded
        name = interaction.command.qualified_name if interaction.command else "unknown"
        log.error("Error in /%s", name, exc_info=error)
        msg = "⚠️ Something went wrong while running that command. The error was logged."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(msg, ephemeral=True)
            else:
                await interaction.response.send_message(msg, ephemeral=True)
        except discord.HTTPException:
            pass


# --------------------------------------------------------------------------- #
# The bot
# --------------------------------------------------------------------------- #
class XzyBot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.moderation = True          # required for on_audit_log_entry_create
        intents.guild_messages = True
        intents.message_content = ENABLE_MESSAGE_CONTENT  # privileged
        super().__init__(
            intents=intents,
            allowed_mentions=discord.AllowedMentions.none(),
            chunk_guilds_at_startup=False,
            max_messages=1000,
        )
        self.tree = SecurityTree(self)
        self.db = Database(DB_PATH)

        # caches (write-through)
        self.cfg_cache: dict[int, dict[str, Any]] = {}
        self.admins: dict[int, set[int]] = defaultdict(set)
        self.whitelist: dict[int, set[int]] = defaultdict(set)
        self.unauth: dict[int, set[str]] = defaultdict(set)
        self.thresholds: dict[tuple[int, str], tuple[int, int]] = {}

        # runtime state
        self.events: dict[tuple[int, int, str], deque] = defaultdict(deque)
        self.handled: dict[tuple[int, int], dict] = {}
        self.locks: dict[tuple[int, int], asyncio.Lock] = defaultdict(asyncio.Lock)
        self.quarantine: dict[int, float] = {}
        self.dirty: set[int] = set()
        self.role_maps: dict[int, dict[int, int]] = defaultdict(dict)
        self.restore_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.unauth_cooldown: dict[tuple[int, int, str], float] = {}
        self.msg_buffer: list[tuple] = []
        self.del_buffer: list[int] = []
        self.audit_stats: dict[int, list[int]] = {}
        self._full_counter = 0
        self._maint_counter = 0

    # ------------------------------------------------------------------ setup
    async def dbx(self, fn, *args):
        return await asyncio.to_thread(fn, *args)

    async def setup_hook(self) -> None:
        await self.load_cache()
        try:
            if DEV_GUILD_ID:
                guild = discord.Object(id=DEV_GUILD_ID)
                self.tree.copy_global_to(guild=guild)
                await self.tree.sync(guild=guild)
                log.info("Synced commands to dev guild %s", DEV_GUILD_ID)
            else:
                await self.tree.sync()
                log.info("Synced global commands")
        except discord.HTTPException:
            log.exception("Command sync failed (commands from a previous sync may still work)")
        self.snapshot_loop.start()
        self.flush_loop.start()
        self.maintenance_loop.start()

    async def load_cache(self) -> None:
        def _load():
            return {
                "cfg": self.db.fetchall("SELECT * FROM guild_settings"),
                "admins": self.db.fetchall("SELECT guild_id, user_id FROM admins"),
                "wl": self.db.fetchall("SELECT guild_id, user_id FROM whitelist"),
                "un": self.db.fetchall("SELECT guild_id, command FROM unauth_commands"),
                "th": self.db.fetchall("SELECT guild_id, action, limit_count, window_seconds FROM thresholds"),
            }
        data = await self.dbx(_load)
        for r in data["cfg"]:
            cfg = self.default_cfg()
            cfg.update({k: r[k] for k in CFG_COLUMNS})
            self.cfg_cache[r["guild_id"]] = cfg
        for r in data["admins"]:
            self.admins[r["guild_id"]].add(r["user_id"])
        for r in data["wl"]:
            self.whitelist[r["guild_id"]].add(r["user_id"])
        for r in data["un"]:
            self.unauth[r["guild_id"]].add(r["command"])
        for r in data["th"]:
            self.thresholds[(r["guild_id"], r["action"])] = (r["limit_count"], r["window_seconds"])
        log.info("Cache loaded: %d guild configs", len(self.cfg_cache))

    @staticmethod
    def default_cfg() -> dict[str, Any]:
        return {
            "alert_channel_id": None, "unauth_channel_id": None, "antinuke_enabled": 1,
            "autorestore_enabled": 1, "punishment": "ban", "punishment_duration": 0,
        }

    def cfg(self, guild_id: int) -> dict[str, Any]:
        c = self.cfg_cache.get(guild_id)
        if c is None:
            c = self.default_cfg()
            self.cfg_cache[guild_id] = c
        return c

    async def set_cfg(self, guild_id: int, **values: Any) -> None:
        self.cfg(guild_id).update(values)
        await self.dbx(self.db.upsert_settings, guild_id, values)

    def threshold(self, guild_id: int, kind: str) -> tuple[int, int]:
        return self.thresholds.get((guild_id, kind), DEFAULT_THRESHOLDS[kind])

    # ------------------------------------------------------------ permissions
    def is_owner(self, guild: discord.Guild, uid: int) -> bool:
        return uid == guild.owner_id or uid in OWNER_IDS

    def is_admin(self, guild: discord.Guild, uid: int) -> bool:
        return self.is_owner(guild, uid) or uid in self.admins.get(guild.id, ())

    def is_exempt(self, guild: discord.Guild, uid: int) -> bool:
        """Never punished by anti-nuke: server owner, this bot, whitelisted IDs."""
        return (uid == guild.owner_id or (self.user is not None and uid == self.user.id)
                or uid in self.whitelist.get(guild.id, ()))

    def is_authorised(self, guild: discord.Guild, uid: int) -> bool:
        return self.is_admin(guild, uid) or uid in self.whitelist.get(guild.id, ())

    async def authorize_interaction(self, interaction: discord.Interaction) -> bool:
        if interaction.type is not discord.InteractionType.application_command:
            return True
        name = interaction.command.qualified_name if interaction.command else "unknown"
        guild = interaction.guild
        if guild is None:
            await self._reply(interaction, "❌ This bot's commands only work inside a server.")
            return False
        if name in PUBLIC_COMMANDS:
            return True
        uid = interaction.user.id
        allowed = self.is_owner(guild, uid) if name in OWNER_ONLY_COMMANDS else self.is_admin(guild, uid)
        if allowed:
            return True
        embed = self.unauth_embed(
            user_id=uid, user_name=str(interaction.user), command=f"/{name}",
            channel_id=interaction.channel_id, action="Command blocked (not a Security Bot Admin)")
        await self.send_log(guild, "unauth", embed)
        need = "the **server owner**" if name in OWNER_ONLY_COMMANDS else "a **Security Bot Admin**"
        await self._reply(interaction, f"⛔ You are not authorised to use `/{name}`. This requires {need}. "
                                       "This attempt has been logged.")
        return False

    @staticmethod
    async def _reply(interaction: discord.Interaction, text: str) -> None:
        try:
            if interaction.response.is_done():
                await interaction.followup.send(text, ephemeral=True)
            else:
                await interaction.response.send_message(text, ephemeral=True)
        except discord.HTTPException:
            pass

    # ---------------------------------------------------------------- logging
    def bot_alert_embed(self, *, event: str, executor_id: Optional[int], executor_name: str,
                        targets: str, threshold: str, punishment: str, restore: str,
                        detail: Optional[str] = None) -> discord.Embed:
        e = discord.Embed(title="🚨 Bot Alert", description=f"**{event}**", colour=COLOR_RED,
                          timestamp=discord.utils.utcnow())
        who = f"{mention(executor_id)} (`{executor_id}`)\n{clip(executor_name, 100)}" if executor_id else "Unknown"
        e.add_field(name="Executor", value=who, inline=True)
        e.add_field(name="Threshold", value=clip(threshold, 200), inline=True)
        e.add_field(name="Target(s)", value=clip(targets or "—", 1000), inline=False)
        if detail:
            e.add_field(name="Details", value=clip(detail, 1000), inline=False)
        e.add_field(name="Punishment", value=clip(punishment, 1000), inline=False)
        e.add_field(name="Auto-Restore", value=clip(restore, 1000), inline=False)
        e.set_footer(text=f"{BOT_NAME} • Anti-Nuke")
        return e

    def unauth_embed(self, *, user_id: int, user_name: str, command: str,
                     channel_id: Optional[int], action: str) -> discord.Embed:
        e = discord.Embed(title="⛔ Unauthorised Command", colour=COLOR_ORANGE,
                          timestamp=discord.utils.utcnow())
        e.add_field(name="User", value=f"{mention(user_id)} (`{user_id}`)\n{clip(user_name, 100)}", inline=True)
        e.add_field(name="Command", value=f"`{clip(command, 200)}`", inline=True)
        e.add_field(name="Channel", value=f"<#{channel_id}>" if channel_id else "Unknown", inline=True)
        e.add_field(name="Action Taken", value=clip(action, 500), inline=False)
        e.set_footer(text=f"{BOT_NAME} • Command Guard")
        return e

    async def send_log(self, guild: discord.Guild, kind: str, embed: discord.Embed) -> bool:
        cfg = self.cfg(guild.id)
        channel_id = cfg["alert_channel_id"] if kind == "alert" else (cfg["unauth_channel_id"] or cfg["alert_channel_id"])
        channel = None
        if channel_id:
            channel = guild.get_channel(channel_id)
            if channel is None:
                try:
                    channel = await self.fetch_channel(channel_id)
                except discord.HTTPException:
                    channel = None
        if isinstance(channel, discord.abc.Messageable):
            try:
                await channel.send(embed=embed)
                return True
            except discord.HTTPException as exc:
                log.warning("Cannot send %s log in guild %s: %s", kind, guild.id, exc)
        if kind == "alert":  # last resort: DM the server owner
            try:
                owner = guild.owner or await self.fetch_user(guild.owner_id)
                await owner.send(content=f"No working log channel is set in **{guild.name}** — use `/setlog`.",
                                 embed=embed)
                return True
            except (discord.HTTPException, AttributeError):
                log.warning("Could not deliver alert for guild %s anywhere", guild.id)
        return False

    async def record_incident(self, guild_id: int, kind: str, executor_id: Optional[int],
                              executor_name: str, details: str, punishment: str, restore: str) -> None:
        try:
            await self.dbx(self.db.execute,
                           "INSERT INTO incidents (guild_id, created_at, kind, executor_id, executor_name, details, "
                           "punishment, restore) VALUES (?,?,?,?,?,?,?,?)",
                           (guild_id, int(time.time()), kind, executor_id, executor_name,
                            clip(details, 1500), clip(punishment, 500), clip(restore, 500)))
        except Exception:
            log.exception("Could not record incident")

    # ------------------------------------------------------------- snapshots
    def under_quarantine(self, guild_id: int) -> bool:
        return self.quarantine.get(guild_id, 0) > time.monotonic()

    async def snapshot_guild(self, guild: discord.Guild) -> tuple[int, int]:
        channels = []
        for ch in guild.channels:
            d = channel_data(ch)
            if d:
                channels.append((ch.id, ch.name, json.dumps(d)))
        roles = []
        for r in guild.roles:
            d = role_data(r)
            if d:
                roles.append((r.id, r.name, json.dumps(d)))

        icon_hash = guild.icon.key if guild.icon else None
        icon_path: Optional[str] = None
        prev = await self.dbx(self.db.fetchone, "SELECT icon_hash, icon_path FROM snap_guild WHERE guild_id=?", (guild.id,))
        if icon_hash:
            if prev and prev["icon_hash"] == icon_hash and prev["icon_path"] and Path(prev["icon_path"]).exists():
                icon_path = prev["icon_path"]
            else:
                try:
                    data = await guild.icon.read()
                    ICON_DIR.mkdir(parents=True, exist_ok=True)
                    path = ICON_DIR / f"{guild.id}_{icon_hash}.bin"
                    await self.dbx(path.write_bytes, data)
                    icon_path = str(path)
                except (discord.HTTPException, OSError):
                    log.warning("Could not store icon for guild %s", guild.id)
                    icon_hash = prev["icon_hash"] if prev else None
                    icon_path = prev["icon_path"] if prev else None
        await self.dbx(self.db.write_snapshot, guild.id, guild.name, icon_hash, icon_path,
                       channels, roles, int(time.time()))
        return len(channels), len(roles)

    @tasks.loop(seconds=30)
    async def snapshot_loop(self) -> None:
        self._full_counter += 1
        if self._full_counter % 30 == 0:  # full refresh every ~15 min
            self.dirty.update(g.id for g in self.guilds)
        for gid in list(self.dirty):
            if self.under_quarantine(gid):
                continue
            self.dirty.discard(gid)
            guild = self.get_guild(gid)
            if guild is None:
                continue
            try:
                await self.snapshot_guild(guild)
            except Exception:
                log.exception("Snapshot failed for guild %s", gid)
                self.dirty.add(gid)

    @snapshot_loop.before_loop
    async def _before_snapshot(self) -> None:
        await self.wait_until_ready()
        self.dirty.update(g.id for g in self.guilds)

    @tasks.loop(seconds=3)
    async def flush_loop(self) -> None:
        await self.flush_messages()

    @flush_loop.before_loop
    async def _before_flush(self) -> None:
        await self.wait_until_ready()

    async def flush_messages(self) -> None:
        if not self.msg_buffer and not self.del_buffer:
            return
        rows, self.msg_buffer = self.msg_buffer, []
        dels, self.del_buffer = self.del_buffer, []
        try:
            await self.dbx(self.db.flush_messages, rows, dels)
        except Exception:
            log.exception("Message backup flush failed (%d rows dropped)", len(rows))

    @tasks.loop(seconds=30)
    async def maintenance_loop(self) -> None:
        now = int(time.time())
        # expire temporary bans
        try:
            due = await self.dbx(self.db.fetchall,
                                 "SELECT guild_id, user_id FROM temp_bans WHERE expires_at <= ?", (now,))
        except Exception:
            log.exception("temp_bans query failed")
            due = []
        for row in due:
            guild = self.get_guild(row["guild_id"])
            if guild is not None:
                try:
                    await guild.unban(discord.Object(id=row["user_id"]), reason=f"{BOT_NAME}: temporary ban expired")
                    log.info("Unbanned %s in %s (expired)", row["user_id"], guild.id)
                except discord.NotFound:
                    pass
                except discord.HTTPException as exc:
                    log.warning("Could not unban %s in %s: %s", row["user_id"], guild.id, exc)
            await self.dbx(self.db.execute, "DELETE FROM temp_bans WHERE guild_id=? AND user_id=?",
                           (row["guild_id"], row["user_id"]))
        # in-memory housekeeping
        mono = time.monotonic()
        for key in [k for k, v in self.handled.items() if mono - v["ts"] > HANDLED_TTL]:
            self.handled.pop(key, None)
        for key in [k for k, v in self.events.items() if not v]:
            self.events.pop(key, None)
        for key in [k for k, v in self.unauth_cooldown.items() if mono - v > 60]:
            self.unauth_cooldown.pop(key, None)
        for key in [k for k, v in self.quarantine.items() if v < mono]:
            self.quarantine.pop(key, None)
        # DB pruning every ~10 minutes
        self._maint_counter += 1
        if self._maint_counter % 20 == 0:
            try:
                await self.dbx(self.db.maintenance, MESSAGE_BACKUP_LIMIT,
                               now - MESSAGE_RETENTION_DAYS * 86400,
                               now - SNAPSHOT_KEEP_DELETED_DAYS * 86400,
                               now - INCIDENT_KEEP_DAYS * 86400)
            except Exception:
                log.exception("Database maintenance failed")

    @maintenance_loop.before_loop
    async def _before_maintenance(self) -> None:
        await self.wait_until_ready()

    # ------------------------------------------------------------ punishments
    async def punish_user(self, guild: discord.Guild, user_id: int, reason: str) -> tuple[bool, str]:
        cfg = self.cfg(guild.id)
        kind, duration = cfg["punishment"], int(cfg["punishment_duration"])
        try:
            if kind == "ban":
                await guild.ban(discord.Object(id=user_id), reason=reason, delete_message_seconds=0)
                if duration > 0:
                    await self.dbx(self.db.execute,
                                   "INSERT OR REPLACE INTO temp_bans (guild_id, user_id, expires_at) VALUES (?,?,?)",
                                   (guild.id, user_id, int(time.time()) + duration))
                return True, f"🔨 Banned ({fmt_duration(duration)})"
            if kind == "kick":
                await guild.kick(discord.Object(id=user_id), reason=reason)
                return True, "👢 Kicked"
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            seconds = min(duration or 3600, MAX_TIMEOUT_SECONDS)
            await member.timeout(timedelta(seconds=seconds), reason=reason)
            return True, f"⏳ Timed out ({fmt_duration(seconds)})"
        except discord.NotFound:
            return True, f"Executor already left the server ({kind} not needed)"
        except discord.Forbidden:
            stripped = await self.strip_dangerous_roles(guild, user_id, reason)
            extra = f" Stripped {stripped} dangerous role(s) as a fallback." if stripped else ""
            return False, (f"❌ {kind} failed — missing permission or role hierarchy "
                           f"(move the bot's role higher).{extra}")
        except discord.HTTPException as exc:
            return False, f"❌ {kind} failed (HTTP {exc.status})"

    async def strip_dangerous_roles(self, guild: discord.Guild, user_id: int, reason: str) -> int:
        try:
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            top = guild.me.top_role
            roles = [r for r in member.roles
                     if not r.is_default() and not r.managed and r < top
                     and any(getattr(r.permissions, p, False) for p in DANGEROUS_PERMS)]
            if roles:
                await member.remove_roles(*roles, reason=reason)
            return len(roles)
        except (discord.HTTPException, AttributeError):
            return 0

    async def remove_bots(self, guild: discord.Guild, bot_ids: list[int], reason: str) -> str:
        done = 0
        for bid in bot_ids:
            try:
                await guild.ban(discord.Object(id=bid), reason=reason, delete_message_seconds=0)
                done += 1
            except discord.HTTPException:
                try:
                    await guild.kick(discord.Object(id=bid), reason=reason)
                    done += 1
                except discord.HTTPException:
                    log.warning("Could not remove bot %s from %s", bid, guild.id)
        return f"Removed {done}/{len(bot_ids)} unauthorized bot(s)"

    # ---------------------------------------------------------------- restore
    def _build_overwrites(self, guild: discord.Guild, items: list[dict], role_map: dict[int, int],
                          include_members: bool = True) -> dict:
        result: dict = {}
        for o in items:
            po = discord.PermissionOverwrite.from_pair(discord.Permissions(o["allow"]), discord.Permissions(o["deny"]))
            if o["type"] == "role":
                role = guild.get_role(role_map.get(o["id"], o["id"]))
                if role is not None:
                    result[role] = po
            elif include_members:
                result[guild.get_member(o["id"]) or discord.Object(id=o["id"], type=discord.Member)] = po
        return result

    async def _create_channel(self, guild: discord.Guild, d: dict, cat_map: dict[int, int],
                              role_map: dict[int, int]) -> discord.abc.GuildChannel:
        reason = f"{BOT_NAME}: auto-restore"
        category = None
        if d.get("category_id"):
            cand = guild.get_channel(cat_map.get(d["category_id"], d["category_id"]))
            category = cand if isinstance(cand, discord.CategoryChannel) else None
        ct = discord.ChannelType
        t = d["type"]
        last_exc: Optional[Exception] = None
        for include_members in (True, False):
            ow = self._build_overwrites(guild, d.get("overwrites", []), role_map, include_members)
            try:
                if t == ct.category.value:
                    return await guild.create_category(name=d["name"], overwrites=ow, position=d["position"], reason=reason)
                if t in (ct.text.value, ct.news.value):
                    kw = dict(name=d["name"], category=category, topic=d.get("topic"), nsfw=bool(d.get("nsfw")),
                              slowmode_delay=d.get("slowmode") or 0, overwrites=ow, position=d["position"], reason=reason)
                    if t == ct.news.value:
                        try:
                            return await guild.create_text_channel(news=True, **kw)
                        except (TypeError, discord.HTTPException):
                            pass
                    return await guild.create_text_channel(**kw)
                if t == ct.voice.value:
                    return await guild.create_voice_channel(
                        name=d["name"], category=category, bitrate=min(d.get("bitrate") or 64000, guild.bitrate_limit),
                        user_limit=d.get("user_limit") or 0, overwrites=ow, position=d["position"], reason=reason)
                if t == ct.stage_voice.value:
                    return await guild.create_stage_channel(name=d["name"], category=category, overwrites=ow,
                                                            position=d["position"], reason=reason)
                if t == ct.forum.value:
                    return await guild.create_forum(name=d["name"], category=category, topic=d.get("topic") or "",
                                                    nsfw=bool(d.get("nsfw")), slowmode_delay=d.get("slowmode") or 0,
                                                    overwrites=ow, position=d["position"], reason=reason)
                raise ValueError(f"unsupported channel type {t}")
            except discord.Forbidden:
                raise
            except discord.HTTPException as exc:  # e.g. stale member overwrite -> retry roles-only
                last_exc = exc
        raise last_exc or RuntimeError("channel creation failed")

    async def restore_channels(self, guild: discord.Guild, ids: list[int]) -> str:
        ids = [i for i in dict.fromkeys(ids) if guild.get_channel(i) is None]
        if not ids:
            return "No channels needed restoring"
        ph = ",".join("?" for _ in ids)
        rows = await self.dbx(self.db.fetchall,
                              f"SELECT channel_id, data FROM snap_channels WHERE guild_id=? AND channel_id IN ({ph})",
                              (guild.id, *ids))
        found = {r["channel_id"]: json.loads(r["data"]) for r in rows}
        missing = len(ids) - len(found)
        order = sorted(found.values(), key=lambda d: (d["type"] != discord.ChannelType.category.value, d["position"]))
        cat_map: dict[int, int] = {}
        role_map = self.role_maps[guild.id]
        restored = failed = replayed = 0
        async with self.restore_locks[guild.id]:
            for d in order:
                try:
                    new = await self._create_channel(guild, d, cat_map, role_map)
                except Exception as exc:
                    failed += 1
                    log.warning("Restore of channel %s failed: %s", d.get("name"), exc)
                    continue
                restored += 1
                if isinstance(new, discord.CategoryChannel):
                    cat_map[d["id"]] = new.id
                replayed += await self.replay_messages(d["id"], new)
                nd = channel_data(new)
                if nd:
                    await self.dbx(self.db.upsert_channel, guild.id, new.id, new.name, json.dumps(nd), int(time.time()))
                await self.dbx(self.db.execute, "DELETE FROM snap_channels WHERE guild_id=? AND channel_id=?",
                               (guild.id, d["id"]))
        parts = [f"Restored {restored}/{len(ids)} channel(s)"]
        if failed:
            parts.append(f"{failed} failed")
        if missing:
            parts.append(f"{missing} had no snapshot")
        if replayed:
            parts.append(f"{replayed} message(s) replayed")
        self.dirty.add(guild.id)
        return ", ".join(parts)

    async def restore_roles(self, guild: discord.Guild, ids: list[int]) -> str:
        ids = [i for i in dict.fromkeys(ids) if guild.get_role(i) is None]
        if not ids:
            return "No roles needed restoring"
        ph = ",".join("?" for _ in ids)
        rows = await self.dbx(self.db.fetchall,
                              f"SELECT role_id, data FROM snap_roles WHERE guild_id=? AND role_id IN ({ph})",
                              (guild.id, *ids))
        found = sorted((json.loads(r["data"]) for r in rows), key=lambda d: d["position"])
        missing = len(ids) - len(found)
        reason = f"{BOT_NAME}: auto-restore"
        new_map: dict[int, int] = {}
        failed = 0
        async with self.restore_locks[guild.id]:
            my_perms = guild.me.guild_permissions.value
            for d in found:
                perms = d["permissions"]
                try:
                    try:
                        role = await guild.create_role(name=d["name"], colour=discord.Colour(d["colour"]),
                                                      hoist=d["hoist"], mentionable=d["mentionable"],
                                                      permissions=discord.Permissions(perms), reason=reason)
                    except discord.Forbidden:  # cannot grant permissions the bot lacks
                        role = await guild.create_role(name=d["name"], colour=discord.Colour(d["colour"]),
                                                      hoist=d["hoist"], mentionable=d["mentionable"],
                                                      permissions=discord.Permissions(perms & my_perms), reason=reason)
                except discord.HTTPException as exc:
                    failed += 1
                    log.warning("Restore of role %s failed: %s", d["name"], exc)
                    continue
                new_map[d["id"]] = role.id
                self.role_maps[guild.id][d["id"]] = role.id
                top = guild.me.top_role.position
                try:
                    await role.edit(position=max(1, min(d["position"], top - 1)), reason=reason)
                except discord.HTTPException:
                    pass
                await self.dbx(self.db.execute, "DELETE FROM snap_roles WHERE guild_id=? AND role_id=?",
                               (guild.id, d["id"]))
            reapplied = await self.reapply_role_overwrites(guild, new_map) if new_map else 0
        parts = [f"Restored {len(new_map)}/{len(ids)} role(s)"]
        if failed:
            parts.append(f"{failed} failed")
        if missing:
            parts.append(f"{missing} had no snapshot")
        if reapplied:
            parts.append(f"{reapplied} channel permission overwrite(s) re-applied")
        parts.append("role members are not restored")
        self.dirty.add(guild.id)
        return ", ".join(parts)

    async def reapply_role_overwrites(self, guild: discord.Guild, role_map: dict[int, int]) -> int:
        rows = await self.dbx(self.db.fetchall,
                              "SELECT channel_id, data FROM snap_channels WHERE guild_id=? AND deleted_at IS NULL",
                              (guild.id,))
        count = 0
        for r in rows:
            ch = guild.get_channel(r["channel_id"])
            if ch is None:
                continue
            for o in json.loads(r["data"]).get("overwrites", []):
                if o["type"] != "role" or o["id"] not in role_map:
                    continue
                role = guild.get_role(role_map[o["id"]])
                if role is None or role in ch.overwrites:
                    continue
                po = discord.PermissionOverwrite.from_pair(discord.Permissions(o["allow"]), discord.Permissions(o["deny"]))
                try:
                    await ch.set_permissions(role, overwrite=po, reason=f"{BOT_NAME}: auto-restore")
                    count += 1
                except discord.HTTPException:
                    pass
        return count

    async def restore_identity(self, guild: discord.Guild) -> str:
        row = await self.dbx(self.db.fetchone, "SELECT * FROM snap_guild WHERE guild_id=?", (guild.id,))
        if row is None:
            return "No server snapshot yet"
        changes, notes = {}, []
        if row["name"] and row["name"] != guild.name:
            changes["name"] = row["name"]
            notes.append("name")
        current_hash = guild.icon.key if guild.icon else None
        if row["icon_hash"] and row["icon_hash"] != current_hash and row["icon_path"] and Path(row["icon_path"]).exists():
            changes["icon"] = await self.dbx(Path(row["icon_path"]).read_bytes)
            notes.append("icon")
        if not changes:
            return "Server name/icon already match the snapshot"
        try:
            await guild.edit(reason=f"{BOT_NAME}: auto-restore", **changes)
            return "Restored server " + " & ".join(notes)
        except discord.HTTPException as exc:
            return f"Could not restore server {' & '.join(notes)} (HTTP {exc.status})"

    async def restore_recent(self, guild: discord.Guild) -> str:
        cutoff = int(time.time()) - RESTORE_LOOKBACK_HOURS * 3600
        roles = await self.dbx(self.db.fetchall,
                               "SELECT role_id FROM snap_roles WHERE guild_id=? AND deleted_at >= ?", (guild.id, cutoff))
        chans = await self.dbx(self.db.fetchall,
                               "SELECT channel_id FROM snap_channels WHERE guild_id=? AND deleted_at >= ?", (guild.id, cutoff))
        self.quarantine[guild.id] = max(self.quarantine.get(guild.id, 0), time.monotonic() + 120)
        lines = [await self.restore_roles(guild, [r["role_id"] for r in roles]),
                 await self.restore_channels(guild, [c["channel_id"] for c in chans]),
                 await self.restore_identity(guild)]
        return "\n".join(f"• {x}" for x in lines)

    async def replay_messages(self, old_channel_id: int, channel: discord.abc.GuildChannel) -> int:
        if not ENABLE_MESSAGE_BACKUP or not isinstance(channel, discord.TextChannel):
            return 0
        rows = await self.dbx(self.db.fetchall,
                              "SELECT * FROM message_backup WHERE channel_id=? ORDER BY message_id DESC LIMIT ?",
                              (old_channel_id, MESSAGE_RESTORE_LIMIT))
        if not rows:
            return 0
        rows = list(reversed(rows))
        hook: Optional[discord.Webhook] = None
        try:
            hook = await channel.create_webhook(name="Xzy Restore", reason=f"{BOT_NAME}: message restore")
        except discord.HTTPException:
            hook = None
        sent = 0
        none = discord.AllowedMentions.none()
        try:
            for r in rows:
                stamp = discord.utils.snowflake_time(r["message_id"]).strftime("%Y-%m-%d %H:%M")
                body = (r["content"] or "")[:1700]
                files = json.loads(r["attachments"] or "[]")
                if files:
                    body += "\n" + "\n".join(files[:5])
                text = f"`{stamp} UTC` {body}".strip()[:2000]
                name = re.sub(r"(?i)discord|clyde", "•", r["author_name"] or "Unknown")[:80]
                if len(name) < 2:
                    name = "Unknown"
                try:
                    if hook is not None:
                        kw: dict[str, Any] = {"content": text, "username": name, "allowed_mentions": none}
                        if r["author_avatar"]:
                            kw["avatar_url"] = r["author_avatar"]
                        await hook.send(**kw)
                    else:
                        await channel.send(f"**{name}**: {text}"[:2000], allowed_mentions=none)
                    sent += 1
                except discord.HTTPException:
                    continue
        finally:
            if hook is not None:
                try:
                    await hook.delete(reason=f"{BOT_NAME}: restore finished")
                except discord.HTTPException:
                    pass
        await self.dbx(self.db.execute, "UPDATE message_backup SET channel_id=? WHERE channel_id=?",
                       (channel.id, old_channel_id))
        return sent

    async def auto_restore(self, guild: discord.Guild, kind: str, targets: list[tuple[Optional[int], str]]) -> str:
        ids = [t[0] for t in targets if t[0]]
        try:
            if kind == "channel_delete":
                return await self.restore_channels(guild, ids)
            if kind == "role_delete":
                return await self.restore_roles(guild, ids)
            if kind == "member_ban":
                n = 0
                for uid in ids:
                    try:
                        await guild.unban(discord.Object(id=uid), reason=f"{BOT_NAME}: reverting mass ban")
                        n += 1
                    except discord.HTTPException:
                        pass
                return f"Unbanned {n}/{len(ids)} victim(s)"
            if kind == "server_name":
                await guild.edit(name=targets[0][1], reason=f"{BOT_NAME}: reverting unauthorized rename")
                return f"Server name reverted to `{clip(targets[0][1], 100)}`"
            if kind in ("channel_create", "role_create"):
                n = 0
                for tid in ids:
                    obj = guild.get_channel(tid) if kind == "channel_create" else guild.get_role(tid)
                    if obj is not None:
                        try:
                            await obj.delete(reason=f"{BOT_NAME}: removing attacker-created item")
                            n += 1
                        except discord.HTTPException:
                            pass
                    table, col = ("snap_channels", "channel_id") if kind == "channel_create" else ("snap_roles", "role_id")
                    await self.dbx(self.db.execute, f"DELETE FROM {table} WHERE guild_id=? AND {col}=?", (guild.id, tid))
                what = "channel(s)" if kind == "channel_create" else "role(s)"
                return f"Deleted {n}/{len(ids)} attacker-created {what}"
            if kind == "webhook_create":
                n = 0
                for tid in ids:
                    try:
                        wh = await self.fetch_webhook(tid)
                        await wh.delete(reason=f"{BOT_NAME}: removing attacker-created webhook")
                        n += 1
                    except discord.HTTPException:
                        pass
                return f"Deleted {n}/{len(ids)} attacker-created webhook(s)"
            if kind == "member_kick":
                return "Kicked members can't be restored automatically (they can rejoin)"
            if kind == "webhook_delete":
                return "Webhooks can't be restored automatically (their tokens are lost)"
            if kind == "bot_add":
                return "N/A (bot removed)"
        except discord.Forbidden:
            return "❌ Restore failed — missing permissions"
        except Exception as exc:
            log.exception("auto_restore(%s) failed", kind)
            return f"❌ Restore failed ({type(exc).__name__})"
        return "N/A"

    # ------------------------------------------------------ violation handling
    def _claim(self, guild_id: int, uid: int) -> tuple[dict, bool]:
        key = (guild_id, uid)
        now = time.monotonic()
        st = self.handled.get(key)
        if st is None or now - st["ts"] > HANDLED_TTL:
            st = {"ts": now, "ok": False, "alerted": 0.0}
            self.handled[key] = st
            return st, True
        return st, False

    async def handle_violation(self, guild: discord.Guild, executor_id: int, executor_name: str,
                               kind: str, targets: list[tuple[Optional[int], str]], st: dict, new: bool,
                               threshold_text: str, detail: Optional[str] = None) -> None:
        self.quarantine[guild.id] = time.monotonic() + QUARANTINE_SECONDS
        cfg = self.cfg(guild.id)
        reason = f"{BOT_NAME}: {KIND_LABELS[kind]}"
        async with self.locks[(guild.id, executor_id)]:
            pre = ""
            if kind == "bot_add":  # neutralise the rogue bot first
                pre = await self.remove_bots(guild, [t[0] for t in targets if t[0]], reason)
            if st["ok"]:
                punish_text = "Executor already punished"
            else:
                ok, punish_text = await self.punish_user(guild, executor_id, reason)
                st["ok"] = ok
            if kind == "bot_add":
                restore_text = pre
            elif cfg["autorestore_enabled"]:
                restore_text = await self.auto_restore(guild, kind, targets)
            else:
                restore_text = "Disabled (`/autorestore`)"
        target_text = ", ".join(t[1] for t in targets) if targets else "—"
        log.warning("[%s] %s by %s (%s) -> %s | %s", guild.id, kind, executor_name, executor_id, punish_text, restore_text)
        now = time.monotonic()
        if new or kind in IMMEDIATE_KINDS or now - st["alerted"] > 30:
            st["alerted"] = now
            await self.record_incident(guild.id, kind, executor_id, executor_name,
                                       f"{target_text} {detail or ''}".strip(), punish_text, restore_text)
            embed = self.bot_alert_embed(event=KIND_LABELS[kind], executor_id=executor_id, executor_name=executor_name,
                                         targets=target_text, threshold=threshold_text, punishment=punish_text,
                                         restore=restore_text, detail=detail)
            await self.send_log(guild, "alert", embed)

    async def process_entry(self, entry: discord.AuditLogEntry) -> None:
        guild = entry.guild
        if guild is None:
            return
        stats = self.audit_stats.setdefault(guild.id, [0, 0])
        stats[0] += 1
        stats[1] = int(time.time())
        uid = entry.user_id
        if uid is None or self.user is None or uid == self.user.id:
            return
        cfg = self.cfg(guild.id)
        action = entry.action
        executor_name = str(entry.user) if entry.user else f"User {uid}"

        if action is discord.AuditLogAction.guild_update:
            old, new_name = getattr(entry.before, "name", None), getattr(entry.after, "name", None)
            if old is None or new_name is None or old == new_name:
                return
            if not cfg["antinuke_enabled"] or self.is_exempt(guild, uid):
                self.dirty.add(guild.id)  # trusted rename -> refresh snapshot
                return
            st, new = self._claim(guild.id, uid)
            await self.handle_violation(guild, uid, executor_name, "server_name", [(None, old)], st, new,
                                        "Immediate (any change)", detail=f"`{clip(old, 100)}` → `{clip(new_name, 100)}`")
            return

        if action is discord.AuditLogAction.bot_add:
            bot_id = entry.target_id
            if not bot_id:
                return
            label = (str(entry.target) if entry.target is not None and hasattr(entry.target, "name")
                     else f"Bot {bot_id}") + f" (`{bot_id}`)"
            if (not cfg["antinuke_enabled"] or self.is_exempt(guild, uid)
                    or bot_id in self.whitelist.get(guild.id, ())):
                why = ("Anti-Nuke is disabled" if not cfg["antinuke_enabled"]
                       else "adder is the owner/whitelisted, or the bot is whitelisted")
                embed = self.bot_alert_embed(event="Bot Added (authorised)", executor_id=uid,
                                             executor_name=executor_name, targets=label, threshold="n/a",
                                             punishment=f"None — {why}", restore="N/A")
                embed.colour = COLOR_GREEN
                await self.send_log(guild, "alert", embed)
                return
            st, new = self._claim(guild.id, uid)
            await self.handle_violation(guild, uid, executor_name, "bot_add", [(bot_id, label)], st, new,
                                        "Immediate (not whitelisted)",
                                        detail="Bot added by a user who is not the owner or whitelisted.")
            return

        if not cfg["antinuke_enabled"] or self.is_exempt(guild, uid):
            return
        kind = TRACKED_ACTIONS.get(action)
        if kind is None:
            return
        limit, window = self.threshold(guild.id, kind)
        now = time.monotonic()
        dq = self.events[(guild.id, uid, kind)]
        while dq and now - dq[0][0] > window:
            dq.popleft()
        tid = entry.target_id
        if kind in ("member_ban", "member_kick"):
            tlabel = f"<@{tid}> (`{tid}`)"
        else:
            nm = getattr(entry.before, "name", None) or getattr(entry.after, "name", None) or "unknown"
            tlabel = f"{nm} (`{tid}`)"
        dq.append((now, tid, tlabel))
        st = self.handled.get((guild.id, uid))
        active = st is not None and now - st["ts"] <= HANDLED_TTL
        if not active and len(dq) < limit:
            return
        targets = [(t, lbl) for _, t, lbl in dq]
        count = len(dq)
        dq.clear()
        st, new = self._claim(guild.id, uid)
        await self.handle_violation(guild, uid, executor_name, kind, targets, st, new,
                                    f"{count}/{limit} within {window}s")

    # ------------------------------------------------------------------ events
    async def on_ready(self) -> None:
        log.info("%s ready as %s in %d guild(s)", BOT_NAME, self.user, len(self.guilds))
        for g in self.guilds:
            self.warn_missing_perms(g)
        if not ENABLE_MESSAGE_CONTENT:
            log.warning("ENABLE_MESSAGE_CONTENT=false: message backup and ! command guard are disabled")

    def warn_missing_perms(self, guild: discord.Guild) -> None:
        missing = [label for attr, label in REQUIRED_PERMS.items() if not getattr(guild.me.guild_permissions, attr)]
        if missing:
            log.warning("[%s] %s is missing permissions: %s", guild.id, guild.name, ", ".join(missing))

    async def on_guild_join(self, guild: discord.Guild) -> None:
        self.dirty.add(guild.id)
        self.warn_missing_perms(guild)

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        try:
            await self.process_entry(entry)
        except Exception:
            log.exception("Failed to process audit log entry %s", getattr(entry, "id", "?"))

    async def on_guild_channel_create(self, channel) -> None:
        self.dirty.add(channel.guild.id)

    async def on_guild_channel_update(self, before, after) -> None:
        self.dirty.add(after.guild.id)

    async def on_guild_channel_delete(self, channel) -> None:
        try:
            await self.dbx(self.db.execute,
                           "UPDATE snap_channels SET deleted_at=? WHERE guild_id=? AND channel_id=? AND deleted_at IS NULL",
                           (int(time.time()), channel.guild.id, channel.id))
        except Exception:
            log.exception("Could not flag deleted channel")

    async def on_guild_role_create(self, role: discord.Role) -> None:
        self.dirty.add(role.guild.id)

    async def on_guild_role_update(self, before: discord.Role, after: discord.Role) -> None:
        self.dirty.add(after.guild.id)

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        try:
            await self.dbx(self.db.execute,
                           "UPDATE snap_roles SET deleted_at=? WHERE guild_id=? AND role_id=? AND deleted_at IS NULL",
                           (int(time.time()), role.guild.id, role.id))
        except Exception:
            log.exception("Could not flag deleted role")

    async def on_guild_update(self, before: discord.Guild, after: discord.Guild) -> None:
        # Snapshot refresh happens only via trusted paths (audit handler / periodic loop).
        pass

    def _queue_message(self, message: discord.Message) -> None:
        if not ENABLE_MESSAGE_BACKUP or not isinstance(message.channel, discord.TextChannel):
            return
        if message.webhook_id or (self.user and message.author.id == self.user.id):
            return
        if not message.content and not message.attachments:
            return
        self.msg_buffer.append((
            message.id, message.guild.id, message.channel.id, message.author.id, message.author.display_name,
            message.author.display_avatar.url, message.content[:4000],
            json.dumps([a.url for a in message.attachments][:10]), int(message.created_at.timestamp()),
        ))
        if len(self.msg_buffer) > 20000:  # safety valve if the DB is stalled
            del self.msg_buffer[:5000]

    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        self._queue_message(message)
        if message.author.bot or message.webhook_id or not message.content:
            return
        await self.check_unauth_message(message)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        if after.guild is not None and not after.author.bot and before.content != after.content:
            self._queue_message(after)

    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        if ENABLE_MESSAGE_BACKUP:
            self.del_buffer.append(payload.message_id)

    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent) -> None:
        if ENABLE_MESSAGE_BACKUP:
            self.del_buffer.extend(payload.message_ids)

    async def check_unauth_message(self, message: discord.Message) -> None:
        guild = message.guild
        content = message.content
        if not content.startswith(UNAUTH_PREFIX):
            return
        cmds = self.unauth.get(guild.id)
        if not cmds:
            return
        parts = content[len(UNAUTH_PREFIX):].split(None, 1)
        if not parts or parts[0].lower() not in cmds:
            return
        if self.is_authorised(guild, message.author.id):
            return
        command = f"{UNAUTH_PREFIX}{parts[0].lower()}"
        try:
            await message.delete()
            action = "Message deleted"
        except discord.Forbidden:
            action = "Could not delete message (missing Manage Messages)"
        except discord.HTTPException:
            action = "Message already deleted"
        key = (guild.id, message.author.id, command)
        now = time.monotonic()
        if now - self.unauth_cooldown.get(key, 0) < 5:
            return  # avoid log spam
        self.unauth_cooldown[key] = now
        embed = self.unauth_embed(user_id=message.author.id, user_name=str(message.author), command=command,
                                  channel_id=message.channel.id, action=action)
        await self.send_log(guild, "unauth", embed)

    async def close(self) -> None:
        try:
            await self.flush_messages()
        except Exception:
            log.exception("Final flush failed")
        await super().close()
        self.db.close()


# --------------------------------------------------------------------------- #
# Slash commands
# --------------------------------------------------------------------------- #
def ok(title: str, text: str, colour: int = COLOR_GREEN) -> discord.Embed:
    return discord.Embed(title=title, description=text, colour=colour)


async def send(interaction: discord.Interaction, embed: discord.Embed, ephemeral: bool = True) -> None:
    if interaction.response.is_done():
        await interaction.followup.send(embed=embed, ephemeral=ephemeral)
    else:
        await interaction.response.send_message(embed=embed, ephemeral=ephemeral)


def register_commands(bot: XzyBot) -> None:
    tree = bot.tree
    admin_only = app_commands.guild_only()

    # ---------------------------------------------------------------- /help
    @tree.command(name="help", description="Show all Xzy Security Bot commands.")
    @admin_only
    async def help_cmd(interaction: discord.Interaction) -> None:
        e = discord.Embed(title=f"🛡️ {BOT_NAME} — Help", colour=COLOR_BLUE,
                          description="Anti-nuke protection powered by Audit Logs. "
                                      "All commands except `/help` require a **Security Bot Admin**.")
        e.add_field(name="Admins", inline=False, value=(
            "`/adminadd` `/adminremove` — manage Security Bot Admins (server owner only)\n"
            "`/adminlist` — list admins"))
        e.add_field(name="Protection", inline=False, value=(
            "`/antinuke` — enable/disable/status\n"
            "`/autorestore` — toggle auto-restore or run a manual restore\n"
            "`/threshold` — set limit/time-window per action\n"
            "`/addpunisment` — choose ban / kick / timeout (+ expiry)\n"
            "`/whitelist` — exempt trusted users / bots\n"
            "`/security` — status, incidents, snapshot refresh"))
        e.add_field(name="Logging & Command Guard", inline=False, value=(
            "`/setlog` — set Bot Alert / Unauthorised Command channels\n"
            f"`/addunauth` `/removeunauth` `/unauthlist` — block `{UNAUTH_PREFIX}commands` for non-admins"))
        e.add_field(name="Detected", inline=False, value=(
            "Mass channel/role deletion • mass channel/role/webhook creation • mass bans/kicks • "
            "webhook deletion • server-name changes • unauthorized bot additions"))
        await send(interaction, e)

    # ------------------------------------------------------------- /adminadd
    @tree.command(name="adminadd", description="Add a Security Bot Admin (server owner only).")
    @admin_only
    @app_commands.describe(user="User to make a Security Bot Admin")
    async def adminadd(interaction: discord.Interaction, user: discord.User) -> None:
        g = interaction.guild
        if user.bot:
            return await send(interaction, ok("❌ Not allowed", "Bots cannot be Security Bot Admins.", COLOR_RED))
        if user.id == g.owner_id or user.id in bot.admins[g.id]:
            return await send(interaction, ok("ℹ️ Already an admin", f"{user.mention} already has access.", COLOR_BLUE))
        await bot.dbx(bot.db.execute, "INSERT OR IGNORE INTO admins (guild_id, user_id, added_by, added_at) VALUES (?,?,?,?)",
                      (g.id, user.id, interaction.user.id, int(time.time())))
        bot.admins[g.id].add(user.id)
        await send(interaction, ok("✅ Admin added", f"{user.mention} is now a Security Bot Admin."))

    @tree.command(name="adminremove", description="Remove a Security Bot Admin (server owner only).")
    @admin_only
    @app_commands.describe(user="Admin to remove")
    async def adminremove(interaction: discord.Interaction, user: discord.User) -> None:
        g = interaction.guild
        if user.id not in bot.admins[g.id]:
            return await send(interaction, ok("ℹ️ Not an admin", f"{user.mention} is not a Security Bot Admin.", COLOR_BLUE))
        await bot.dbx(bot.db.execute, "DELETE FROM admins WHERE guild_id=? AND user_id=?", (g.id, user.id))
        bot.admins[g.id].discard(user.id)
        await send(interaction, ok("✅ Admin removed", f"{user.mention} is no longer a Security Bot Admin."))

    @tree.command(name="adminlist", description="List Security Bot Admins.")
    @admin_only
    async def adminlist(interaction: discord.Interaction) -> None:
        g = interaction.guild
        lines = [f"👑 {mention(g.owner_id)} (server owner)"] + [f"🛡️ {mention(u)}" for u in sorted(bot.admins[g.id])]
        await send(interaction, ok("Security Bot Admins", clip("\n".join(lines), 4000), COLOR_BLUE))

    # --------------------------------------------------------------- /setlog
    @tree.command(name="setlog", description="Set the channel for Bot Alert / Unauthorised Command logs.")
    @admin_only
    @app_commands.describe(channel="Channel that receives the logs", log_type="Which log to send there (default: both)")
    @app_commands.choices(log_type=[
        app_commands.Choice(name="Both", value="all"),
        app_commands.Choice(name="Bot Alert", value="alert"),
        app_commands.Choice(name="Unauthorised Command", value="unauth"),
    ])
    async def setlog(interaction: discord.Interaction, channel: discord.TextChannel, log_type: str = "all") -> None:
        perms = channel.permissions_for(interaction.guild.me)
        if not (perms.view_channel and perms.send_messages and perms.embed_links):
            return await send(interaction, ok("❌ Missing permissions",
                                              f"I need **View Channel, Send Messages and Embed Links** in {channel.mention}.", COLOR_RED))
        values: dict[str, Any] = {}
        if log_type in ("all", "alert"):
            values["alert_channel_id"] = channel.id
        if log_type in ("all", "unauth"):
            values["unauth_channel_id"] = channel.id
        await bot.set_cfg(interaction.guild.id, **values)
        label = {"all": "Bot Alert and Unauthorised Command", "alert": "Bot Alert", "unauth": "Unauthorised Command"}[log_type]
        await send(interaction, ok("✅ Log channel set", f"**{label}** logs will be sent to {channel.mention}."))

    # ------------------------------------------------------------- /antinuke
    @tree.command(name="antinuke", description="Enable, disable or view anti-nuke protection.")
    @admin_only
    @app_commands.describe(action="What to do")
    @app_commands.choices(action=[
        app_commands.Choice(name="Enable", value="enable"),
        app_commands.Choice(name="Disable", value="disable"),
        app_commands.Choice(name="Status", value="status"),
    ])
    async def antinuke(interaction: discord.Interaction, action: str = "status") -> None:
        gid = interaction.guild.id
        if action in ("enable", "disable"):
            await bot.set_cfg(gid, antinuke_enabled=1 if action == "enable" else 0)
        on = bool(bot.cfg(gid)["antinuke_enabled"])
        await send(interaction, ok("🛡️ Anti-Nuke", f"Protection is **{'ENABLED' if on else 'DISABLED'}**.",
                                   COLOR_GREEN if on else COLOR_RED))

    # ----------------------------------------------------------- /autorestore
    @tree.command(name="autorestore", description="Toggle auto-restore or restore recently deleted items.")
    @admin_only
    @app_commands.describe(action="What to do")
    @app_commands.choices(action=[
        app_commands.Choice(name="Enable", value="enable"),
        app_commands.Choice(name="Disable", value="disable"),
        app_commands.Choice(name="Status", value="status"),
        app_commands.Choice(name="Restore now (recently deleted items, name, icon)", value="restore_now"),
    ])
    async def autorestore(interaction: discord.Interaction, action: str = "status") -> None:
        gid = interaction.guild.id
        if action == "restore_now":
            await interaction.response.defer(ephemeral=True, thinking=True)
            try:
                result = await bot.restore_recent(interaction.guild)
            except Exception:
                log.exception("restore_now failed")
                result = "❌ Restore failed — see the bot log."
            return await send(interaction, ok("♻️ Restore finished", clip(result, 4000), COLOR_BLUE))
        if action in ("enable", "disable"):
            await bot.set_cfg(gid, autorestore_enabled=1 if action == "enable" else 0)
        on = bool(bot.cfg(gid)["autorestore_enabled"])
        await send(interaction, ok("♻️ Auto-Restore", f"Auto-restore is **{'ENABLED' if on else 'DISABLED'}**.",
                                   COLOR_GREEN if on else COLOR_RED))

    # ------------------------------------------------------------ /whitelist
    @tree.command(name="whitelist", description="Manage users/bots exempt from anti-nuke.")
    @admin_only
    @app_commands.describe(action="Add, remove or list", user="User or bot (required for add/remove)")
    @app_commands.choices(action=[
        app_commands.Choice(name="Add", value="add"),
        app_commands.Choice(name="Remove", value="remove"),
        app_commands.Choice(name="List", value="list"),
    ])
    async def whitelist(interaction: discord.Interaction, action: str, user: Optional[discord.User] = None) -> None:
        gid = interaction.guild.id
        if action == "list":
            ids = sorted(bot.whitelist[gid])
            text = "\n".join(f"• {mention(i)} (`{i}`)" for i in ids) or "Nobody is whitelisted."
            return await send(interaction, ok("Whitelist", clip(text, 4000), COLOR_BLUE))
        if user is None:
            return await send(interaction, ok("❌ Missing user", "Choose a `user` for add/remove.", COLOR_RED))
        if action == "add":
            await bot.dbx(bot.db.execute, "INSERT OR IGNORE INTO whitelist (guild_id, user_id, added_by, added_at) VALUES (?,?,?,?)",
                          (gid, user.id, interaction.user.id, int(time.time())))
            bot.whitelist[gid].add(user.id)
            extra = " (a whitelisted bot may also be added to the server)" if user.bot else ""
            return await send(interaction, ok("✅ Whitelisted", f"{user.mention} is exempt from anti-nuke{extra}."))
        await bot.dbx(bot.db.execute, "DELETE FROM whitelist WHERE guild_id=? AND user_id=?", (gid, user.id))
        bot.whitelist[gid].discard(user.id)
        await send(interaction, ok("✅ Removed", f"{user.mention} is no longer whitelisted."))

    # --------------------------------------------------------- /addpunisment
    @tree.command(name="addpunisment", description="Set the punishment: ban, kick or timeout (with optional expiry).")
    @admin_only
    @app_commands.describe(punishment="Punishment for offenders",
                           duration="e.g. 30m, 12h, 7d, 1w. Ban: 0 = permanent. Timeout default 1h (max 28d)")
    @app_commands.choices(punishment=[
        app_commands.Choice(name="Ban", value="ban"),
        app_commands.Choice(name="Kick", value="kick"),
        app_commands.Choice(name="Timeout", value="timeout"),
    ])
    async def addpunisment(interaction: discord.Interaction, punishment: str, duration: Optional[str] = None) -> None:
        seconds = 0
        if punishment == "kick":
            seconds = 0
        elif duration is None:
            seconds = 3600 if punishment == "timeout" else 0
        else:
            parsed = parse_duration(duration)
            if parsed is None:
                return await send(interaction, ok("❌ Invalid duration", "Use values like `30m`, `12h`, `7d`, `1w` or `0`.", COLOR_RED))
            seconds = parsed
        if punishment == "timeout" and not (60 <= seconds <= MAX_TIMEOUT_SECONDS):
            return await send(interaction, ok("❌ Invalid timeout", "Timeouts must be between `1m` and `28d`.", COLOR_RED))
        if punishment == "ban" and 0 < seconds < 60:
            return await send(interaction, ok("❌ Invalid ban length", "Temporary bans must be at least `1m`.", COLOR_RED))
        await bot.set_cfg(interaction.guild.id, punishment=punishment, punishment_duration=seconds)
        text = {"ban": f"🔨 **Ban** ({fmt_duration(seconds)})", "kick": "👢 **Kick**",
                "timeout": f"⏳ **Timeout** ({fmt_duration(seconds)})"}[punishment]
        await send(interaction, ok("✅ Punishment updated", f"Offenders will receive: {text}"))

    # ------------------------------------------------------ unauthorised cmds
    @tree.command(name="addunauth", description=f"Block a {UNAUTH_PREFIX}command for non-admins.")
    @admin_only
    @app_commands.describe(command=f"Command name, e.g. ban (for {UNAUTH_PREFIX}ban)")
    async def addunauth(interaction: discord.Interaction, command: str) -> None:
        cmd = normalise_command(command)
        if cmd is None:
            return await send(interaction, ok("❌ Invalid command", "Use 1–32 letters, numbers, `_` or `-`.", COLOR_RED))
        gid = interaction.guild.id
        await bot.dbx(bot.db.execute, "INSERT OR IGNORE INTO unauth_commands (guild_id, command, added_by, added_at) VALUES (?,?,?,?)",
                      (gid, cmd, interaction.user.id, int(time.time())))
        bot.unauth[gid].add(cmd)
        note = "" if ENABLE_MESSAGE_CONTENT else "\n⚠️ `ENABLE_MESSAGE_CONTENT` is false, so this guard is inactive."
        await send(interaction, ok("✅ Command blocked",
                                   f"`{UNAUTH_PREFIX}{cmd}` is now unauthorised for non-admins.{note}"))

    @tree.command(name="removeunauth", description=f"Stop blocking a {UNAUTH_PREFIX}command.")
    @admin_only
    @app_commands.describe(command="Command name to unblock")
    async def removeunauth(interaction: discord.Interaction, command: str) -> None:
        cmd = normalise_command(command)
        gid = interaction.guild.id
        if cmd is None or cmd not in bot.unauth[gid]:
            return await send(interaction, ok("ℹ️ Not found", "That command is not in the unauthorised list.", COLOR_BLUE))
        await bot.dbx(bot.db.execute, "DELETE FROM unauth_commands WHERE guild_id=? AND command=?", (gid, cmd))
        bot.unauth[gid].discard(cmd)
        await send(interaction, ok("✅ Command unblocked", f"`{UNAUTH_PREFIX}{cmd}` is no longer blocked."))

    @tree.command(name="unauthlist", description="List blocked (unauthorised) commands.")
    @admin_only
    async def unauthlist(interaction: discord.Interaction) -> None:
        cmds = sorted(bot.unauth[interaction.guild.id])
        text = "\n".join(f"• `{UNAUTH_PREFIX}{c}`" for c in cmds) or "No commands are blocked."
        await send(interaction, ok("Unauthorised commands", clip(text, 4000), COLOR_BLUE))

    # ------------------------------------------------------------ /threshold
    @tree.command(name="threshold", description="View or set how many actions in how long trigger punishment.")
    @admin_only
    @app_commands.describe(action="Which action to configure (omit to view all)",
                           limit="Number of actions that triggers punishment",
                           window="Time window in seconds")
    @app_commands.choices(action=[
        app_commands.Choice(name="Channel deletions", value="channel_delete"),
        app_commands.Choice(name="Role deletions", value="role_delete"),
        app_commands.Choice(name="Member bans", value="member_ban"),
        app_commands.Choice(name="Webhook deletions", value="webhook_delete"),
        app_commands.Choice(name="Member kicks", value="member_kick"),
        app_commands.Choice(name="Channel creations (spam)", value="channel_create"),
        app_commands.Choice(name="Role creations (spam)", value="role_create"),
        app_commands.Choice(name="Webhook creations (spam)", value="webhook_create"),
    ])
    async def threshold(interaction: discord.Interaction, action: Optional[str] = None,
                        limit: Optional[app_commands.Range[int, 1, 50]] = None,
                        window: Optional[app_commands.Range[int, 1, 3600]] = None) -> None:
        gid = interaction.guild.id
        if action and (limit is not None or window is not None):
            cur_limit, cur_window = bot.threshold(gid, action)
            new_limit, new_window = limit or cur_limit, window or cur_window
            await bot.dbx(bot.db.execute,
                          "INSERT INTO thresholds (guild_id, action, limit_count, window_seconds) VALUES (?,?,?,?) "
                          "ON CONFLICT(guild_id, action) DO UPDATE SET limit_count=excluded.limit_count, "
                          "window_seconds=excluded.window_seconds", (gid, action, new_limit, new_window))
            bot.thresholds[(gid, action)] = (new_limit, new_window)
        elif limit is not None or window is not None:
            return await send(interaction, ok("❌ Choose an action", "Pick which `action` the limit/window applies to.", COLOR_RED))
        lines = []
        for key in DEFAULT_THRESHOLDS:
            lim, win = bot.threshold(gid, key)
            lines.append(f"• **{KIND_LABELS[key]}**: `{lim}` within `{win}s`")
        lines.append(f"• **{KIND_LABELS['bot_add']}**: immediate")
        lines.append(f"• **{KIND_LABELS['server_name']}**: immediate")
        await send(interaction, ok("📏 Thresholds", "\n".join(lines), COLOR_BLUE))

    # ------------------------------------------------------------- /security
    @tree.command(name="security", description="Security status, recent incidents or refresh the snapshot.")
    @admin_only
    @app_commands.describe(view="What to show")
    @app_commands.choices(view=[
        app_commands.Choice(name="Status", value="status"),
        app_commands.Choice(name="Recent incidents", value="incidents"),
        app_commands.Choice(name="Refresh snapshot now", value="snapshot"),
    ])
    async def security(interaction: discord.Interaction, view: str = "status") -> None:
        g = interaction.guild
        await interaction.response.defer(ephemeral=True, thinking=True)
        if view == "snapshot":
            if bot.under_quarantine(g.id):
                return await send(interaction, ok("⏸️ Snapshots paused",
                                                  "A violation was handled recently; snapshots are paused to protect the "
                                                  "last trusted state. Try again in a few minutes.", COLOR_ORANGE))
            channels, roles = await bot.snapshot_guild(g)
            return await send(interaction, ok("📸 Snapshot refreshed", f"Saved **{channels}** channels and **{roles}** roles, "
                                                                      "plus the server name and icon."))
        if view == "incidents":
            rows = await bot.dbx(bot.db.fetchall,
                                 "SELECT created_at, kind, executor_id, punishment FROM incidents WHERE guild_id=? "
                                 "ORDER BY id DESC LIMIT 10", (g.id,))
            if not rows:
                return await send(interaction, ok("📜 Recent incidents", "No incidents recorded. 🎉", COLOR_GREEN))
            lines = [f"<t:{r['created_at']}:R> **{KIND_LABELS.get(r['kind'], r['kind'])}** by "
                     f"{mention(r['executor_id']) if r['executor_id'] else 'unknown'} — {clip(r['punishment'] or '—', 80)}"
                     for r in rows]
            return await send(interaction, ok("📜 Recent incidents", clip("\n".join(lines), 4000), COLOR_ORANGE))

        cfg = bot.cfg(g.id)
        now = int(time.time())
        snap = await bot.dbx(bot.db.fetchone, "SELECT updated_at FROM snap_guild WHERE guild_id=?", (g.id,))
        counts = await bot.dbx(bot.db.fetchone,
                               "SELECT (SELECT COUNT(*) FROM snap_channels WHERE guild_id=:g AND deleted_at IS NULL) AS ch, "
                               "(SELECT COUNT(*) FROM snap_roles WHERE guild_id=:g AND deleted_at IS NULL) AS ro, "
                               "(SELECT COUNT(*) FROM message_backup WHERE guild_id=:g) AS msgs, "
                               "(SELECT COUNT(*) FROM incidents WHERE guild_id=:g) AS inc, "
                               "(SELECT COUNT(*) FROM incidents WHERE guild_id=:g AND created_at > :d) AS inc24", {"g": g.id, "d": now - 86400})
        missing = [label for attr, label in REQUIRED_PERMS.items() if not getattr(g.me.guild_permissions, attr)]
        punishment = cfg["punishment"] + ("" if cfg["punishment"] == "kick" else f" ({fmt_duration(cfg['punishment_duration'])})")

        def chan(cid):
            return f"<#{cid}>" if cid else "not set"

        e = discord.Embed(title=f"🛡️ {BOT_NAME} — Security Status", colour=COLOR_RED if missing else COLOR_GREEN,
                          timestamp=discord.utils.utcnow())
        e.add_field(name="Anti-Nuke", value="✅ Enabled" if cfg["antinuke_enabled"] else "❌ Disabled", inline=True)
        e.add_field(name="Auto-Restore", value="✅ Enabled" if cfg["autorestore_enabled"] else "❌ Disabled", inline=True)
        e.add_field(name="Punishment", value=punishment, inline=True)
        e.add_field(name="Bot Alert log", value=chan(cfg["alert_channel_id"]), inline=True)
        e.add_field(name="Unauthorised log", value=chan(cfg["unauth_channel_id"] or cfg["alert_channel_id"]), inline=True)
        e.add_field(name="People", value=f"{len(bot.admins[g.id])} admin(s) • {len(bot.whitelist[g.id])} whitelisted", inline=True)
        e.add_field(name="Blocked commands", value=str(len(bot.unauth[g.id])), inline=True)
        e.add_field(name="Snapshot", value=(f"<t:{snap['updated_at']}:R>\n{counts['ch']} channels • {counts['ro']} roles"
                                            if snap else "none yet"), inline=True)
        e.add_field(name="Message backup", value=(f"{counts['msgs']} stored" if ENABLE_MESSAGE_BACKUP else "disabled"), inline=True)
        e.add_field(name="Incidents", value=f"{counts['inc']} total • {counts['inc24']} in 24h", inline=True)
        stats = bot.audit_stats.get(g.id)
        e.add_field(name="Audit events", inline=True,
                    value=(f"{stats[0]} received • last <t:{stats[1]}:R>" if stats
                           else "⚠️ none since bot start (check View Audit Log permission)"))
        above = len([r for r in g.roles if r > g.me.top_role])
        if above:
            e.add_field(name="⚠️ Role hierarchy", inline=False,
                        value=f"{above} role(s) are above the bot's role. Users/bots in them can NOT be punished — "
                              "drag the bot's role to the top.")
        if bot.under_quarantine(g.id):
            e.add_field(name="⚠️ Snapshots paused", value="Recent violation — last trusted snapshot is protected.", inline=False)
        if missing:
            e.add_field(name="❌ Missing bot permissions", value=", ".join(missing), inline=False)
        e.set_footer(text=BOT_NAME)
        await send(interaction, e)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def main() -> None:
    setup_logging()
    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token:
        log.critical("DISCORD_TOKEN is missing. Copy .env.example to .env and fill it in.")
        sys.exit(1)
    bot = XzyBot()
    register_commands(bot)
    try:
        bot.run(token, log_handler=None)
    except discord.LoginFailure:
        log.critical("Invalid DISCORD_TOKEN.")
        sys.exit(1)
    except discord.PrivilegedIntentsRequired:
        log.critical("Enable the 'Message Content Intent' in the Developer Portal (Bot tab), "
                     "or set ENABLE_MESSAGE_CONTENT=false in .env.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
