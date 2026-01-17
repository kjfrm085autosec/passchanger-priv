import discord
from discord.ext import commands
import asyncio
import subprocess
import json
from datetime import datetime
import shlex
import logging
import shutil
import os
import random
import string
import threading
import time
from dotenv import load_dotenv

load_dotenv()

# ============= CONFIGURATION SECTION =============
DISCORD_BOT_TOKEN = ""  # Put your bot token here
BOT_NAME = "EMERALD HOSTS"
BOT_VERSION = "V1"
THUMBNAIL_IMAGE_URL = "https://i.postimg.cc/XYYnZGG5/trashed-1765164388-image-3.jpg"
FOOTER_ICON_URL = "https://i.postimg.cc/XYYnZGG5/trashed-1765164388-image-3.jpg"
MESSAGES_GIF_URL = "https://i.postimg.cc/htW4t2B7/200w-(1).webp"

# LXC Storage Pool
DEFAULT_STORAGE_POOL = "default"

# Crystal Cloud Blue theme colors
COLOR_PRIMARY = 0x5dade2    # Crystal Blue
COLOR_SUCCESS = 0x3498db    # Sky Blue
COLOR_ERROR = 0x2980b9      # Deep Blue
COLOR_INFO = 0x85c1e9       # Light Crystal Blue
COLOR_WARNING = 0xaed6f1    # Soft Cloud Blue

# Payment Configuration
PAYMENT_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"
PAYMENT_METHODS = {
    "Bitcoin": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "Ethereum": "0x1234567890abcdef1234567890abcdef12345678",
    "PayPal": "paypal.me/emeraldhosts",
    "CashApp": "$emeraldhosts"
}

# Game Settings
TIC_TAC_TOE_REWARD = 50  # Credits for winning tic-tac-toe
ROCK_PAPER_SCISSORS_REWARD = 30  # Credits for winning RPS
NUMBER_GUESS_REWARD = 40  # Credits for winning number guess
TRIVIA_REWARD = 35  # Credits for correct trivia answer

# Trial VPS Settings
TRIAL_VPS_DURATION_DAYS = 3  # Trial VPS duration
# ============= END CONFIGURATION =============

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('vps_bot')

if not shutil.which("lxc"):
    logger.error("LXC command not found.")
    raise SystemExit("LXC command not found.")

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='.', intents=intents, help_command=None)

# Main admin user ID
MAIN_ADMIN_ID = 1061287786755395585
VPS_USER_ROLE_ID = None
CPU_THRESHOLD = 90
CHECK_INTERVAL = 60
cpu_monitor_active = True
protected_users = set()

# Message tracking
MESSAGE_REWARD = 15
MESSAGE_THRESHOLD = 50

# Plans & Pricing
PLANS = {
    "Starter": {"ram": "4GB", "cpu": "1", "storage": 20, "price_intel": 42, "price_amd": 83},
    "Basic": {"ram": "8GB", "cpu": "1", "storage": 30, "price_intel": 96, "price_amd": 164},
    "Standard": {"ram": "12GB", "cpu": "2", "storage": 50, "price_intel": 192, "price_amd": 320},
    "Pro": {"ram": "16GB", "cpu": "2", "storage": 80, "price_intel": 220, "price_amd": 340}
}

# JSON helpers
def load_json_file(path: str, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning(f"{path} not found or invalid - initializing default")
        return default

user_data = load_json_file('user_data.json', {})
vps_data = load_json_file('vps_data.json', {})
admin_data = load_json_file('admin_data.json', {"admins": [str(MAIN_ADMIN_ID)]})
protected_data = load_json_file('protected_users.json', {"protected": []})
game_settings = load_json_file('game_settings.json', {
    "tic_tac_toe_reward": TIC_TAC_TOE_REWARD,
    "rock_paper_scissors_reward": ROCK_PAPER_SCISSORS_REWARD,
    "number_guess_reward": NUMBER_GUESS_REWARD,
    "trivia_reward": TRIVIA_REWARD
})
trial_vps_data = load_json_file('trial_vps.json', {})
protected_users = set(protected_data.get("protected", []))

def save_data():
    try:
        with open('user_data.json', 'w') as f:
            json.dump(user_data, f, indent=4)
        with open('vps_data.json', 'w') as f:
            json.dump(vps_data, f, indent=4)
        with open('admin_data.json', 'w') as f:
            json.dump(admin_data, f, indent=4)
        with open('protected_users.json', 'w') as f:
            json.dump({"protected": list(protected_users)}, f, indent=4)
        with open('game_settings.json', 'w') as f:
            json.dump(game_settings, f, indent=4)
        with open('trial_vps.json', 'w') as f:
            json.dump(trial_vps_data, f, indent=4)
        logger.info("Data saved")
    except Exception as e:
        logger.exception(f"Failed to save data: {e}")

# Permission checks
def is_admin():
    async def predicate(ctx):
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        await ctx.send(embed=create_error_embed("Access Denied", "You don't have permission to use this command."))
        return False
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        await ctx.send(embed=create_error_embed("Access Denied", "Only the main admin can use this command."))
        return False
    return commands.check(predicate)

# Embeds
def create_embed(title, description="", color=COLOR_PRIMARY, fields=None):
    embed = discord.Embed(title=f"☁️ {title}", description=description, color=color)
    embed.set_thumbnail(url=THUMBNAIL_IMAGE_URL)
    if fields:
        for field in fields:
            embed.add_field(name=f"💎 {field['name']}", value=field['value'], inline=field.get('inline', False))
    embed.set_footer(text=f"{BOT_NAME} {BOT_VERSION} • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                     icon_url=FOOTER_ICON_URL)
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=COLOR_SUCCESS)

def create_error_embed(title, description=""):
    return create_embed(title, description, color=COLOR_ERROR)

def create_info_embed(title, description=""):
    return create_embed(title, description, color=COLOR_INFO)

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=COLOR_WARNING)

# LXC execution
async def execute_lxc(command, timeout=300):
    try:
        logger.info(f"Executing: {command}")
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        out = stdout.decode().strip() if stdout else ""
        err = stderr.decode().strip() if stderr else ""
        
        if proc.returncode != 0:
            logger.error(f"LXC error ({proc.returncode}): {err}")
            raise Exception(err or f"LXC returned code {proc.returncode}")
        return out or True
    except asyncio.TimeoutError:
        logger.error(f"LXC command timed out: {command}")
        raise Exception(f"Command timed out after {timeout} seconds")
    except ConnectionResetError:
        logger.error(f"Connection reset during LXC command: {command}")
        raise Exception("Connection was reset. Please try again.")
    except BrokenPipeError:
        logger.error(f"Broken pipe during LXC command: {command}")
        raise Exception("Connection lost. Please try again.")
    except Exception as e:
        logger.exception(f"LXC execution failed: {e}")
        raise

# CPU monitor
def get_cpu_usage():
    try:
        result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
        output = result.stdout
        for line in output.split('\n'):
            if '%Cpu(s):' in line or 'Cpu(s):' in line:
                parts = line.split(',')
                for part in parts:
                    if 'id' in part:
                        try:
                            idle = float(part.split('%')[0].split()[-1])
                            return 100.0 - idle
                        except:
                            continue
        return 0.0
    except Exception as e:
        logger.exception(f"Error reading CPU usage: {e}")
        return 0.0

def cpu_monitor():
    global cpu_monitor_active
    while cpu_monitor_active:
        try:
            cpu_usage = get_cpu_usage()
            logger.info(f"CPU usage: {cpu_usage}%")
            if cpu_usage > CPU_THRESHOLD:
                logger.warning(f"CPU {cpu_usage}% > threshold {CPU_THRESHOLD}% — stopping all VPS")
                try:
                    subprocess.run(['lxc', 'stop', '--all', '--force'], check=True)
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                    save_data()
                except Exception as e:
                    logger.exception(f"Failed to stop all VPS: {e}")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            logger.exception(f"CPU monitor error: {e}")
            time.sleep(CHECK_INTERVAL)

cpu_thread = threading.Thread(target=cpu_monitor, daemon=True)
cpu_thread.start()

# Disk resizing
async def set_root_disk_size(container_name: str, size_gb: int):
    try:
        await execute_lxc(f"lxc config device set {container_name} root size={size_gb}GB")
    except Exception as e:
        logger.exception(f"Failed to override root device size for {container_name}: {e}")
        raise
    
    try:
        cmd = (
            "apt-get update -y && apt-get install -y cloud-guest-utils || true; "
            "growpart /dev/sda 1 || true; "
            "if command -v resize2fs >/dev/null 2>&1; then resize2fs /dev/sda1 || true; fi; "
            "if command -v xfs_growfs >/dev/null 2>&1; then xfs_growfs / || true; fi"
        )
        await execute_lxc(f"lxc exec {container_name} -- bash -lc \"{cmd}\"", timeout=240)
    except Exception as e:
        logger.warning(f"Automatic filesystem grow may have failed in {container_name}: {e}")

# Core create function
async def core_create_container(container_name: str, ram_gb: int, cpu: int, storage_gb: int, storage_pool: str = None):
    if storage_pool is None:
        storage_pool = DEFAULT_STORAGE_POOL
    
    try:
        ram_mb = int(ram_gb) * 1024
        
        # Create container with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                await execute_lxc(f"lxc launch images:debian/12 {container_name} --config limits.memory={ram_mb}MB --config limits.cpu={cpu} -s {storage_pool}", timeout=600)
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Attempt {attempt + 1} failed, retrying... Error: {e}")
                await asyncio.sleep(5)
        
        # Set disk size with retry
        await set_root_disk_size(container_name, storage_gb)
        
    except Exception as e:
        # Cleanup on failure
        try:
            await execute_lxc(f"lxc delete {container_name} --force")
        except:
            pass
        raise Exception(f"Failed to create container: {str(e)}")

# VPS Role
async def get_or_create_vps_role(guild):
    global VPS_USER_ROLE_ID
    
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    
    role = discord.utils.get(guild.roles, name="VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    
    try:
        role = await guild.create_role(
            name="VPS User",
            color=discord.Color.blue(),
            reason="VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create VPS User role: {e}")
        return None

# Generate random container name
def generate_container_name():
    prefix = "vps"
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}-{random_chars}"

# MESSAGE REWARD SYSTEM
@bot.event
async def on_message(message):
    if message.author.bot:
        return
    
    await bot.process_commands(message)
    
    user_id = str(message.author.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
    
    user_data[user_id]["messages"] = user_data[user_id].get("messages", 0) + 1
    
    if user_data[user_id]["messages"] % MESSAGE_THRESHOLD == 0:
        user_data[user_id]["credits"] += MESSAGE_REWARD
        save_data()
        try:
            reward_embed = create_success_embed(
                "🎉 Message Milestone Reward!",
                f"Congratulations! You've sent {user_data[user_id]['messages']} messages!"
            )
            reward_embed.add_field(name="💰 Reward", value=f"+{MESSAGE_REWARD} credits", inline=False)
            reward_embed.add_field(name="💳 New Balance", value=f"{user_data[user_id]['credits']} credits", inline=False)
            reward_embed.add_field(name="📊 Next Milestone", value=f"{((user_data[user_id]['messages'] // MESSAGE_THRESHOLD) + 1) * MESSAGE_THRESHOLD} messages", inline=False)
            await message.author.send(embed=reward_embed)
        except discord.Forbidden:
            pass
    else:
        save_data()

# ========== TIC TAC TOE GAME ==========
class TicTacToeButton(discord.ui.Button):
    def __init__(self, x: int, y: int):
        super().__init__(style=discord.ButtonStyle.secondary, label='\u200b', row=y)
        self.x = x
        self.y = y

    async def callback(self, interaction: discord.Interaction):
        view: TicTacToeView = self.view
        if interaction.user != view.current_player:
            await interaction.response.send_message("It's not your turn!", ephemeral=True)
            return
        
        if view.board[self.y][self.x] != 0:
            await interaction.response.send_message("That space is already taken!", ephemeral=True)
            return

        view.board[self.y][self.x] = view.current_mark
        self.style = discord.ButtonStyle.success if view.current_mark == 1 else discord.ButtonStyle.danger
        self.label = 'X' if view.current_mark == 1 else 'O'
        self.disabled = True

        winner = view.check_winner()
        if winner:
            for child in view.children:
                child.disabled = True
            
            if winner == 3:
                result_embed = create_info_embed("🤝 It's a Tie!", "The game ended in a draw!")
                await interaction.response.edit_message(embed=result_embed, view=view)
            else:
                winner_player = view.player1 if winner == 1 else view.player2
                reward = game_settings.get("tic_tac_toe_reward", TIC_TAC_TOE_REWARD)
                
                winner_id = str(winner_player.id)
                if winner_id not in user_data:
                    user_data[winner_id] = {"credits": 0, "messages": 0}
                user_data[winner_id]["credits"] += reward
                save_data()
                
                result_embed = create_success_embed(
                    f"🎉 {winner_player.name} Wins!",
                    f"Congratulations! You won **{reward} credits**!"
                )
                result_embed.add_field(name="Winner", value=winner_player.mention, inline=True)
                result_embed.add_field(name="Reward", value=f"{reward} credits", inline=True)
                result_embed.add_field(name="New Balance", value=f"{user_data[winner_id]['credits']} credits", inline=True)
                await interaction.response.edit_message(embed=result_embed, view=view)
            
            view.stop()
        else:
            view.current_mark = 2 if view.current_mark == 1 else 1
            view.current_player = view.player2 if view.current_mark == 2 else view.player1
            
            game_embed = create_embed(
                "⭕ Tic-Tac-Toe ❌",
                f"**{view.player1.name}** (X) vs **{view.player2.name}** (O)\n\n"
                f"Current Turn: **{view.current_player.name}** {'❌' if view.current_mark == 1 else '⭕'}",
                COLOR_INFO
            )
            game_embed.add_field(name="Reward", value=f"Winner gets **{game_settings.get('tic_tac_toe_reward', TIC_TAC_TOE_REWARD)} credits**!", inline=False)
            await interaction.response.edit_message(embed=game_embed, view=view)

class TicTacToeView(discord.ui.View):
    def __init__(self, player1: discord.Member, player2: discord.Member):
        super().__init__(timeout=300)
        self.player1 = player1
        self.player2 = player2
        self.current_player = player1
        self.current_mark = 1
        self.board = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        
        for y in range(3):
            for x in range(3):
                self.add_item(TicTacToeButton(x, y))

    def check_winner(self):
        # Check rows
        for row in self.board:
            if row[0] == row[1] == row[2] != 0:
                return row[0]
        
        # Check columns
        for col in range(3):
            if self.board[0][col] == self.board[1][col] == self.board[2][col] != 0:
                return self.board[0][col]
        
        # Check diagonals
        if self.board[0][0] == self.board[1][1] == self.board[2][2] != 0:
            return self.board[0][0]
        if self.board[0][2] == self.board[1][1] == self.board[2][0] != 0:
            return self.board[0][2]
        
        # Check for tie
        if all(self.board[y][x] != 0 for y in range(3) for x in range(3)):
            return 3
        
        return None

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True

@bot.command(name='play-tic-tac-toe')
async def play_tic_tac_toe(ctx, opponent: discord.Member = None):
    """Start a tic-tac-toe game"""
    if not opponent:
        await ctx.send(embed=create_error_embed(
            "Missing Opponent",
            "Usage: `.play-tic-tac-toe @opponent`\nExample: `.play-tic-tac-toe @user`"
        ))
        return
    
    if opponent.bot:
        await ctx.send(embed=create_error_embed("Invalid Opponent", "You cannot play against a bot!"))
        return
    
    if opponent.id == ctx.author.id:
        await ctx.send(embed=create_error_embed("Invalid Opponent", "You cannot play against yourself!"))
        return
    
    reward = game_settings.get("tic_tac_toe_reward", TIC_TAC_TOE_REWARD)
    
    confirm_embed = create_embed(
        "🎮 Tic-Tac-Toe Challenge!",
        f"{opponent.mention}, {ctx.author.mention} has challenged you to Tic-Tac-Toe!\n\n"
        f"**Reward:** Winner gets **{reward} credits**!\n\n"
        f"Do you accept?",
        COLOR_INFO
    )
    
    class AcceptView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
            self.accepted = False
        
        @discord.ui.button(label="✅ Accept", style=discord.ButtonStyle.success)
        async def accept(self, interaction: discord.Interaction, button: discord.ui.Button):
            if interaction.user.id != opponent.id:
                await interaction.response.send_message("This challenge is not for you!", ephemeral=True)
                return
            
            self.accepted = True
            self.stop()
            
            game_view = TicTacToeView(ctx.author, opponent)
            game_embed = create_embed(
                "⭕ Tic-Tac-Toe ❌",
                f"**{ctx.author.name}** (X) vs **{opponent.name}** (O)\n\n"
                f"Current Turn: **{ctx.author.name}** ❌",
                COLOR_INFO
            )
            game_embed.add_field(name="Reward", value=f"Winner gets **{reward} credits**!", inline=False)
            
            await interaction.response.edit_message(embed=game_embed, view=game_view)
        
        @discord.ui.button(label="❌ Decline", style=discord.ButtonStyle.danger)
        async def decline(self, interaction: discord.Interaction, button: discord.ui.Button):
            if interaction.user.id != opponent.id:
                await interaction.response.send_message("This challenge is not for you!", ephemeral=True)
                return
            
            self.stop()
            await interaction.response.edit_message(
                embed=create_info_embed("Challenge Declined", f"{opponent.mention} declined the challenge."),
                view=None
            )
    
    view = AcceptView()
    await ctx.send(embed=confirm_embed, view=view)

# ========== ROCK PAPER SCISSORS GAME ==========
@bot.command(name='play-rps')
async def play_rps(ctx, opponent: discord.Member = None):
    """Play Rock Paper Scissors"""
    if not opponent:
        await ctx.send(embed=create_error_embed(
            "Missing Opponent",
            "Usage: `.play-rps @opponent`\nExample: `.play-rps @user`"
        ))
        return
    
    if opponent.bot:
        await ctx.send(embed=create_error_embed("Invalid Opponent", "You cannot play against a bot!"))
        return
    
    if opponent.id == ctx.author.id:
        await ctx.send(embed=create_error_embed("Invalid Opponent", "You cannot play against yourself!"))
        return
    
    reward = game_settings.get("rock_paper_scissors_reward", ROCK_PAPER_SCISSORS_REWARD)
    
    class RPSButton(discord.ui.Button):
        def __init__(self, choice: str, emoji: str):
            super().__init__(style=discord.ButtonStyle.primary, label=choice, emoji=emoji)
            self.choice = choice
    
    class RPSView(discord.ui.View):
        def __init__(self, player1, player2):
            super().__init__(timeout=60)
            self.player1 = player1
            self.player2 = player2
            self.choices = {}
            
            for choice, emoji in [("Rock", "🪨"), ("Paper", "📄"), ("Scissors", "✂️")]:
                button = RPSButton(choice, emoji)
                button.callback = self.make_callback(choice)
                self.add_item(button)
        
        def make_callback(self, choice):
            async def callback(interaction: discord.Interaction):
                if interaction.user.id not in [self.player1.id, self.player2.id]:
                    await interaction.response.send_message("This game is not for you!", ephemeral=True)
                    return
                
                if interaction.user.id in self.choices:
                    await interaction.response.send_message("You already made your choice!", ephemeral=True)
                    return
                
                self.choices[interaction.user.id] = choice
                await interaction.response.send_message(f"You chose {choice}!", ephemeral=True)
                
                if len(self.choices) == 2:
                    await self.determine_winner(interaction)
            
            return callback
        
        async def determine_winner(self, interaction):
            p1_choice = self.choices[self.player1.id]
            p2_choice = self.choices[self.player2.id]
            
            result_embed = create_embed("🎮 Rock Paper Scissors - Results", "", COLOR_INFO)
            result_embed.add_field(name=f"{self.player1.name}", value=p1_choice, inline=True)
            result_embed.add_field(name="VS", value="⚔️", inline=True)
            result_embed.add_field(name=f"{self.player2.name}", value=p2_choice, inline=True)
            
            winner = None
            if p1_choice == p2_choice:
                result_embed.description = "🤝 **It's a Tie!**"
                result_embed.color = COLOR_INFO
            elif (p1_choice == "Rock" and p2_choice == "Scissors") or \
                 (p1_choice == "Paper" and p2_choice == "Rock") or \
                 (p1_choice == "Scissors" and p2_choice == "Paper"):
                winner = self.player1
            else:
                winner = self.player2
            
            if winner:
                winner_id = str(winner.id)
                if winner_id not in user_data:
                    user_data[winner_id] = {"credits": 0, "messages": 0}
                user_data[winner_id]["credits"] += reward
                save_data()
                
                result_embed.description = f"🎉 **{winner.mention} Wins!**\n+{reward} credits!"
                result_embed.color = COLOR_SUCCESS
            
            for child in self.children:
                child.disabled = True
            
            await interaction.message.edit(embed=result_embed, view=self)
            self.stop()
    
    game_embed = create_embed(
        "🎮 Rock Paper Scissors Challenge!",
        f"{ctx.author.mention} challenges {opponent.mention}!\n\n"
        f"**Reward:** Winner gets **{reward} credits**!\n\n"
        f"Both players: Choose your move!",
        COLOR_INFO
    )
    
    await ctx.send(embed=game_embed, view=RPSView(ctx.author, opponent))

# ========== NUMBER GUESSING GAME ==========
@bot.command(name='play-guess')
async def play_guess(ctx):
    """Play Number Guessing Game"""
    reward = game_settings.get("number_guess_reward", NUMBER_GUESS_REWARD)
    
    number = random.randint(1, 100)
    attempts = 0
    max_attempts = 7
    
    game_embed = create_embed(
        "🎲 Number Guessing Game",
        f"I'm thinking of a number between **1 and 100**!\n\n"
        f"You have **{max_attempts} attempts** to guess it.\n"
        f"**Reward:** {reward} credits if you win!\n\n"
        f"Reply with your guess!",
        COLOR_INFO
    )
    
    await ctx.send(embed=game_embed)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel and m.content.isdigit()
    
    while attempts < max_attempts:
        try:
            msg = await bot.wait_for('message', timeout=60.0, check=check)
            attempts += 1
            guess = int(msg.content)
            
            if guess < 1 or guess > 100:
                await ctx.send(embed=create_warning_embed("Invalid Guess", "Please guess between 1 and 100!"))
                attempts -= 1
                continue
            
            remaining = max_attempts - attempts
            
            if guess == number:
                user_id = str(ctx.author.id)
                if user_id not in user_data:
                    user_data[user_id] = {"credits": 0, "messages": 0}
                user_data[user_id]["credits"] += reward
                save_data()
                
                win_embed = create_success_embed(
                    "🎉 Correct!",
                    f"You guessed it in **{attempts}** attempts!\n\n"
                    f"The number was **{number}**!\n"
                    f"You won **{reward} credits**!"
                )
                await ctx.send(embed=win_embed)
                return
            elif guess < number:
                hint_embed = create_info_embed(
                    "📈 Too Low!",
                    f"The number is **higher** than {guess}!\n"
                    f"Attempts remaining: **{remaining}**"
                )
                await ctx.send(embed=hint_embed)
            else:
                hint_embed = create_info_embed(
                    "📉 Too High!",
                    f"The number is **lower** than {guess}!\n"
                    f"Attempts remaining: **{remaining}**"
                )
                await ctx.send(embed=hint_embed)
                
        except asyncio.TimeoutError:
            timeout_embed = create_error_embed(
                "⏰ Time's Up!",
                f"You took too long to respond!\n"
                f"The number was **{number}**."
            )
            await ctx.send(embed=timeout_embed)
            return
    
    lose_embed = create_error_embed(
        "😔 Game Over!",
        f"You've used all {max_attempts} attempts!\n"
        f"The number was **{number}**.\n\n"
        f"Try again with `.play-guess`!"
    )
    await ctx.send(embed=lose_embed)

# ========== TRIVIA GAME ==========
@bot.command(name='play-trivia')
async def play_trivia(ctx):
    """Play Trivia Quiz"""
    reward = game_settings.get("trivia_reward", TRIVIA_REWARD)
    
    trivia_questions = [
        {"q": "What is the capital of France?", "a": ["Paris", "paris"], "cat": "Geography"},
        {"q": "What is 7 x 8?", "a": ["56"], "cat": "Math"},
        {"q": "Who painted the Mona Lisa?", "a": ["Leonardo da Vinci", "Da Vinci", "Leonardo"], "cat": "Art"},
        {"q": "What is the largest planet in our solar system?", "a": ["Jupiter", "jupiter"], "cat": "Science"},
        {"q": "What year did World War II end?", "a": ["1945"], "cat": "History"},
        {"q": "What is the chemical symbol for gold?", "a": ["Au", "au"], "cat": "Chemistry"},
        {"q": "Who wrote Romeo and Juliet?", "a": ["Shakespeare", "William Shakespeare"], "cat": "Literature"},
        {"q": "What is the speed of light in km/s (approx)?", "a": ["300000", "299792"], "cat": "Physics"},
        {"q": "What is the smallest prime number?", "a": ["2"], "cat": "Math"},
        {"q": "What is the capital of Japan?", "a": ["Tokyo", "tokyo"], "cat": "Geography"},
    ]
    
    question = random.choice(trivia_questions)
    
    trivia_embed = create_embed(
        "🧠 Trivia Quiz",
        f"**Category:** {question['cat']}\n\n"
        f"**Question:**\n{question['q']}\n\n"
        f"**Reward:** {reward} credits for correct answer!\n\n"
        f"You have **30 seconds** to answer!",
        COLOR_INFO
    )
    
    await ctx.send(embed=trivia_embed)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    try:
        msg = await bot.wait_for('message', timeout=30.0, check=check)
        
        if msg.content.strip() in question['a']:
            user_id = str(ctx.author.id)
            if user_id not in user_data:
                user_data[user_id] = {"credits": 0, "messages": 0}
            user_data[user_id]["credits"] += reward
            save_data()
            
            correct_embed = create_success_embed(
                "✅ Correct!",
                f"Well done! You got it right!\n\n"
                f"**Answer:** {question['a'][0]}\n"
                f"**Reward:** +{reward} credits!"
            )
            await ctx.send(embed=correct_embed)
        else:
            wrong_embed = create_error_embed(
                "❌ Wrong Answer!",
                f"Sorry, that's incorrect!\n\n"
                f"**Correct Answer:** {question['a'][0]}\n\n"
                f"Try again with `.play-trivia`!"
            )
            await ctx.send(embed=wrong_embed)
            
    except asyncio.TimeoutError:
        timeout_embed = create_error_embed(
            "⏰ Time's Up!",
            f"You took too long to answer!\n\n"
            f"**Correct Answer:** {question['a'][0]}"
        )
        await ctx.send(embed=timeout_embed)

# ========== TRIAL VPS COMMAND ==========
@bot.command(name='trial')
async def trial_vps(ctx):
    """Get a free 3-day trial VPS"""
    user_id = str(ctx.author.id)
    
    # Check if user already used trial
    if user_id in trial_vps_data:
        await ctx.send(embed=create_error_embed(
            "Trial Already Used",
            f"You've already used your free trial!\n\n"
            f"**Trial VPS:** `{trial_vps_data[user_id].get('container_name', 'Unknown')}`\n"
            f"**Status:** {trial_vps_data[user_id].get('status', 'Unknown')}\n\n"
            f"Purchase a plan with `.plans` to get more VPS!"
        ))
        return
    
    confirm_embed = create_info_embed(
        "🎁 Free Trial VPS",
        f"Get a **FREE** trial VPS for {TRIAL_VPS_DURATION_DAYS} days!\n\n"
        f"**Specifications:**\n"
        f"• **RAM:** 2GB\n"
        f"• **CPU:** 1 core\n"
        f"• **Storage:** 10GB\n"
        f"• **Duration:** {TRIAL_VPS_DURATION_DAYS} days\n\n"
        f"⚠️ **Note:** You can only use this once!\n\n"
        f"Do you want to claim your free trial?"
    )
    
    class TrialConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="✅ Claim Trial", style=discord.ButtonStyle.success)
        async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
            if interaction.user.id != ctx.author.id:
                await interaction.response.send_message("This is not for you!", ephemeral=True)
                return
            
            await interaction.response.defer()
            
            container_name = generate_container_name()
            
            try:
                creating_embed = create_info_embed(
                    "🔨 Creating Trial VPS",
                    f"Please wait while we set up your trial VPS...\n"
                    f"This may take a few minutes."
                )
                await interaction.followup.send(embed=creating_embed)
                
                await core_create_container(
                    container_name=container_name,
                    ram_gb=2,
                    cpu=1,
                    storage_gb=10
                )
                
                expiry_date = datetime.now()
                from datetime import timedelta
                expiry_date = expiry_date + timedelta(days=TRIAL_VPS_DURATION_DAYS)
                
                trial_vps_data[user_id] = {
                    'container_name': container_name,
                    'status': 'running',
                    'created_at': datetime.now().isoformat(),
                    'expires_at': expiry_date.isoformat()
                }
                
                if user_id not in vps_data:
                    vps_data[user_id] = []
                
                vps_info = {
                    'name': 'Trial VPS',
                    'container_name': container_name,
                    'plan': 'Trial',
                    'ram': '2GB',
                    'cpu': '1',
                    'storage': 10,
                    'status': 'running',
                    'created_at': datetime.now().isoformat(),
                    'expires_at': expiry_date.isoformat(),
                    'is_trial': True
                }
                
                vps_data[user_id].append(vps_info)
                save_data()
                
                try:
                    vps_role = await get_or_create_vps_role(ctx.guild)
                    if vps_role:
                        await ctx.author.add_roles(vps_role)
                except:
                    pass
                
                success_embed = create_success_embed(
                    "🎉 Trial VPS Created!",
                    f"Your free trial VPS is ready!"
                )
                success_embed.add_field(name="Container", value=f"`{container_name}`", inline=False)
                success_embed.add_field(name="Specifications",
                    value=f"**RAM:** 2GB\n**CPU:** 1 core\n**Storage:** 10GB", inline=True)
                success_embed.add_field(name="Duration",
                    value=f"{TRIAL_VPS_DURATION_DAYS} days", inline=True)
                success_embed.add_field(name="Expires",
                    value=expiry_date.strftime('%Y-%m-%d %H:%M'), inline=True)
                success_embed.add_field(name="Management",
                    value="Use `.manage` to control your VPS!", inline=False)
                
                try:
                    await ctx.author.send(embed=success_embed)
                    await interaction.followup.send(embed=create_success_embed(
                        "✅ Trial Claimed!",
                        "Check your DMs for VPS details!"
                    ))
                except discord.Forbidden:
                    await interaction.followup.send(embed=success_embed)
                    
            except Exception as e:
                logger.error(f"Trial VPS creation failed: {e}")
                await interaction.followup.send(embed=create_error_embed(
                    "Creation Failed",
                    f"Failed to create trial VPS: {str(e)[:100]}"
                ))
        
        @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
            if interaction.user.id != ctx.author.id:
                await interaction.response.send_message("This is not for you!", ephemeral=True)
                return
            
            await interaction.response.edit_message(
                embed=create_info_embed("Cancelled", "Trial VPS claim cancelled."),
                view=None
            )
    
    await ctx.send(embed=confirm_embed, view=TrialConfirmView())

# ========== USER COMMANDS ==========
@bot.command(name='ping')
async def ping_command(ctx):
    latency_ms = round(bot.latency * 1000)
    
    if latency_ms < 100:
        quality = "🟢 **Excellent**"
        color = COLOR_SUCCESS
    elif latency_ms < 200:
        quality = "🟡 **Good**"
        color = COLOR_INFO
    elif latency_ms < 300:
        quality = "🟠 **Fair**"
        color = COLOR_WARNING
    else:
        quality = "🔴 **Potato**"
        color = COLOR_ERROR
    
    embed = create_embed("🏓 Pong!", f"Bot latency and connection status", color)
    embed.add_field(name="⚡ Latency", value=f"**{latency_ms}ms**", inline=True)
    embed.add_field(name="📡 Quality", value=quality, inline=True)
    embed.add_field(name="🌐 Status", value="✅ **Online**", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='messages')
async def messages_command(ctx):
    user_id = str(ctx.author.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
        save_data()
    
    messages_sent = user_data[user_id].get("messages", 0)
    next_milestone = ((messages_sent // MESSAGE_THRESHOLD) + 1) * MESSAGE_THRESHOLD
    progress = messages_sent % MESSAGE_THRESHOLD
    
    embed = create_embed("📊 Message Statistics", f"Your messaging activity and rewards", COLOR_INFO)
    embed.set_image(url=MESSAGES_GIF_URL)
    embed.add_field(name="💬 Total Messages", value=f"**{messages_sent}** messages", inline=True)
    embed.add_field(name="🎁 Rewards Earned", value=f"**{(messages_sent // MESSAGE_THRESHOLD) * MESSAGE_REWARD}** credits", inline=True)
    embed.add_field(name="💳 Current Balance", value=f"**{user_data[user_id]['credits']}** credits", inline=True)
    
    bar_length = 20
    filled = int((progress / MESSAGE_THRESHOLD) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    embed.add_field(
        name="📈 Progress to Next Reward",
        value=f"{bar} **{progress}/{MESSAGE_THRESHOLD}**\n**Next milestone:** {next_milestone} messages = +{MESSAGE_REWARD} credits",
        inline=False
    )
    
    await ctx.send(embed=embed)

@bot.command(name='fix-internet')
async def fix_internet(ctx):
    embed = create_embed(
        "🌐 Container Internet Speed Fix",
        "Complete guide to optimize network performance in your VPS",
        COLOR_INFO
    )
    
    fix_guide = (
        "**Step 1: Update DNS Settings**\n"
        "```bash\n"
        "echo 'nameserver 8.8.8.8' > /etc/resolv.conf\n"
        "echo 'nameserver 1.1.1.1' >> /etc/resolv.conf\n"
        "```\n\n"
        "**Step 2: Optimize Network Stack**\n"
        "```bash\n"
        "sysctl -w net.core.rmem_max=134217728\n"
        "sysctl -w net.core.wmem_max=134217728\n"
        "sysctl -w net.ipv4.tcp_rmem='4096 87380 67108864'\n"
        "sysctl -w net.ipv4.tcp_wmem='4096 65536 67108864'\n"
        "```\n\n"
        "**Step 3: Disable IPv6 (if causing issues)**\n"
        "```bash\n"
        "sysctl -w net.ipv6.conf.all.disable_ipv6=1\n"
        "sysctl -w net.ipv6.conf.default.disable_ipv6=1\n"
        "```"
    )
    embed.add_field(name="🔧 Quick Fixes", value=fix_guide, inline=False)
    
    persistent_fix = (
        "To make changes persistent across reboots:\n"
        "```bash\n"
        "nano /etc/sysctl.conf\n"
        "# Add the following lines:\n"
        "net.core.rmem_max=134217728\n"
        "net.core.wmem_max=134217728\n"
        "net.ipv4.tcp_rmem=4096 87380 67108864\n"
        "net.ipv4.tcp_wmem=4096 65536 67108864\n"
        "```\n"
        "Then run: sysctl -p"
    )
    embed.add_field(name="💾 Persistent Configuration", value=persistent_fix, inline=False)
    
    testing = (
        "**Test Download Speed:**\n"
        "wget -O /dev/null http://speedtest.wdc01.softlayer.com/downloads/test100.zip\n\n"
        "**Test Connectivity:**\n"
        "ping -c 4 8.8.8.8\n\n"
        "**Check DNS:**\n"
        "nslookup google.com"
    )
    embed.add_field(name="🧪 Testing", value=testing, inline=False)
    
    try:
        await ctx.author.send(embed=embed)
        await ctx.send(embed=create_success_embed("Guide Sent!", "Check your DMs for the complete internet speed optimization guide!"))
    except discord.Forbidden:
        await ctx.send(embed=create_error_embed("DM Failed", "Enable DMs to receive the guide!"))

@bot.command(name='plans')
async def show_plans(ctx):
    embed = create_embed("💰 VPS Plans & Pricing", "Choose the perfect plan for your needs:", COLOR_PRIMARY)
    
    for plan_name, plan_details in PLANS.items():
        embed.add_field(
            name=f"▸ {plan_name}",
            value=f"**RAM:** {plan_details['ram']}\n"
                  f"**CPU:** {plan_details['cpu']} cores\n"
                  f"**Storage:** {plan_details['storage']}GB\n"
                  f"**Intel:** ${plan_details['price_intel']}/month\n"
                  f"**AMD:** ${plan_details['price_amd']}/month",
            inline=True
        )
    
    embed.add_field(
        name="📝 How to Order",
        value="1. Use `.buyc` to view payment methods\n"
              "2. Use `.buywc [plan]` to purchase\n"
              "3. Contact admin after payment",
        inline=False
    )
    
    await ctx.send(embed=embed)

@bot.command(name='buyc')
async def buy_credits(ctx):
    embed = create_embed("💳 Purchase Credits", "Choose your payment method:", COLOR_INFO)
    
    payment_info = ""
    for method, address in PAYMENT_METHODS.items():
        payment_info += f"**{method}:** `{address}`\n"
    
    embed.add_field(name="💰 Payment Methods", value=payment_info, inline=False)
    
    embed.add_field(
        name="📋 Instructions",
        value="1. Send payment to any address above\n"
              "2. Contact admin with proof of payment\n"
              "3. Your credits will be added manually\n"
              "4. Use `.credits` to check your balance",
        inline=False
    )
    
    embed.add_field(
        name="💎 Credit Values",
        value="**$1 = 100 credits**\n"
              "**$5 = 550 credits** (+10% bonus)\n"
              "**$10 = 1200 credits** (+20% bonus)\n"
              "**$20 = 2600 credits** (+30% bonus)",
        inline=False
    )
    
    try:
        await ctx.author.send(embed=embed)
        await ctx.send(embed=create_success_embed("Payment Info Sent!", "Check your DMs for payment methods!"))
    except discord.Forbidden:
        await ctx.send(embed=create_error_embed("DM Failed", "Enable DMs to receive payment info!"))

@bot.command(name='buywc')
async def buy_with_credits(ctx, plan_name: str = None):
    if not plan_name:
        await ctx.send(embed=create_error_embed("Missing Plan", "Usage: `.buywc [plan_name]`\nExample: `.buywc Starter`"))
        return
    
    plan_name = plan_name.capitalize()
    if plan_name not in PLANS:
        await ctx.send(embed=create_error_embed("Invalid Plan", 
            f"Available plans: {', '.join(PLANS.keys())}"))
        return
    
    user_id = str(ctx.author.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
        save_data()
    
    plan_details = PLANS[plan_name]
    price = (plan_details['price_intel'] + plan_details['price_amd']) // 2
    credit_cost = price * 100
    
    if user_data[user_id]['credits'] < credit_cost:
        await ctx.send(embed=create_error_embed(
            "Insufficient Credits",
            f"You need {credit_cost} credits for {plan_name} plan.\n"
            f"You have: {user_data[user_id]['credits']} credits\n"
            f"Use `.buyc` to purchase more credits."
        ))
        return
    
    confirm_embed = create_warning_embed("⚠️ Confirm Purchase", 
        f"**Plan:** {plan_name}\n"
        f"**Cost:** {credit_cost} credits\n"
        f"**Your balance:** {user_data[user_id]['credits']} credits\n\n"
        f"Proceed with purchase?")
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="✅ Confirm", style=discord.ButtonStyle.success)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            if interaction.user.id != ctx.author.id:
                await interaction.response.send_message("This is not your purchase!", ephemeral=True)
                return
            
            await interaction.response.defer()
            
            user_data[user_id]['credits'] -= credit_cost
            
            container_name = generate_container_name()
            try:
                await core_create_container(
                    container_name=container_name,
                    ram_gb=int(plan_details['ram'].replace('GB', '')),
                    cpu=int(plan_details['cpu']),
                    storage_gb=plan_details['storage']
                )
                
                if user_id not in vps_data:
                    vps_data[user_id] = []
                
                vps_info = {
                    'name': f"{plan_name} VPS",
                    'container_name': container_name,
                    'plan': plan_name,
                    'ram': plan_details['ram'],
                    'cpu': plan_details['cpu'],
                    'storage': plan_details['storage'],
                    'status': 'running',
                    'created_at': datetime.now().isoformat()
                }
                
                vps_data[user_id].append(vps_info)
                save_data()
                
                try:
                    vps_role = await get_or_create_vps_role(ctx.guild)
                    if vps_role:
                        await ctx.author.add_roles(vps_role)
                except:
                    pass
                
                success_embed = create_success_embed(
                    "✅ VPS Created Successfully!",
                    f"Your {plan_name} VPS is now ready!"
                )
                success_embed.add_field(name="Container Name", value=f"`{container_name}`", inline=False)
                success_embed.add_field(name="Specifications", 
                    value=f"**RAM:** {plan_details['ram']}\n"
                          f"**CPU:** {plan_details['cpu']} cores\n"
                          f"**Storage:** {plan_details['storage']}GB", inline=False)
                success_embed.add_field(name="Connection Info", 
                    value=f"IP will be assigned automatically\n"
                          f"Use `.manage` to control your VPS", inline=False)
                
                try:
                    await ctx.author.send(embed=success_embed)
                    await interaction.followup.send(embed=create_success_embed(
                        "Purchase Complete!",
                        f"Check your DMs for VPS details!"
                    ))
                except discord.Forbidden:
                    await interaction.followup.send(embed=success_embed)
                
            except Exception as e:
                user_data[user_id]['credits'] += credit_cost
                save_data()
                logger.error(f"VPS creation failed: {e}")
                await interaction.followup.send(embed=create_error_embed(
                    "Creation Failed",
                    f"Failed to create VPS: {str(e)[:100]}"
                ))
        
        @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.danger)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            if interaction.user.id != ctx.author.id:
                await interaction.response.send_message("This is not your purchase!", ephemeral=True)
                return
            
            await interaction.response.edit_message(
                embed=create_info_embed("Purchase Cancelled", "No credits were deducted."),
                view=None
            )
    
    await ctx.send(embed=confirm_embed, view=ConfirmView())

@bot.command(name='manage')
async def manage_vps(ctx):
    user_id = str(ctx.author.id)
    
    if user_id not in vps_data or not vps_data[user_id]:
        await ctx.send(embed=create_error_embed("No VPS Found", "You don't have any VPS. Use `.plans` to view available plans."))
        return
    
    embed = create_embed("🛠️ Manage Your VPS", "Select a VPS to manage:", COLOR_INFO)
    
    for i, vps in enumerate(vps_data[user_id], 1):
        status_emoji = "🟢" if vps.get('status') == 'running' else "🔴"
        embed.add_field(
            name=f"#{i} {status_emoji} {vps.get('name', 'Unnamed')}",
            value=f"**Plan:** {vps.get('plan', 'N/A')}\n"
                  f"**Container:** `{vps['container_name']}`\n"
                  f"**Status:** {vps.get('status', 'unknown')}\n"
                  f"**Specs:** {vps.get('ram', 'N/A')} RAM, {vps.get('cpu', 'N/A')} CPU, {vps.get('storage', 'N/A')}GB",
            inline=False
        )
    
    embed.add_field(
        name="📋 Management Options",
        value="Reply with:\n"
              "**start [number]** - Start VPS\n"
              "**stop [number]** - Stop VPS\n"
              "**restart [number]** - Restart VPS\n"
              "**info [number]** - View VPS info\n"
              "**ssh [number]** - Get SSH access via tmate\n"
              "**delete [number]** - Delete VPS\n"
              "Type `cancel` to exit",
        inline=False
    )
    
    await ctx.send(embed=embed)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    try:
        msg = await bot.wait_for('message', timeout=60.0, check=check)
        
        if msg.content.lower() == 'cancel':
            await ctx.send(embed=create_info_embed("Cancelled", "Management cancelled."))
            return
        
        parts = msg.content.split()
        if len(parts) < 2:
            await ctx.send(embed=create_error_embed("Invalid Input", "Usage: [action] [number]"))
            return
        
        action = parts[0].lower()
        try:
            vps_num = int(parts[1]) - 1
            if vps_num < 0 or vps_num >= len(vps_data[user_id]):
                await ctx.send(embed=create_error_embed("Invalid Number", f"Please choose 1-{len(vps_data[user_id])}"))
                return
        except ValueError:
            await ctx.send(embed=create_error_embed("Invalid Number", "Please enter a valid number."))
            return
        
        vps = vps_data[user_id][vps_num]
        container_name = vps['container_name']
        
        if action == 'start':
            try:
                await execute_lxc(f"lxc start {container_name}")
                vps['status'] = 'running'
                save_data()
                await ctx.send(embed=create_success_embed("VPS Started", f"{vps.get('name')} has been started."))
            except Exception as e:
                await ctx.send(embed=create_error_embed("Start Failed", str(e)))
        
        elif action == 'stop':
            try:
                await execute_lxc(f"lxc stop {container_name}")
                vps['status'] = 'stopped'
                save_data()
                await ctx.send(embed=create_success_embed("VPS Stopped", f"{vps.get('name')} has been stopped."))
            except Exception as e:
                await ctx.send(embed=create_error_embed("Stop Failed", str(e)))
        
        elif action == 'restart':
            try:
                await execute_lxc(f"lxc restart {container_name}")
                vps['status'] = 'running'
                save_data()
                await ctx.send(embed=create_success_embed("VPS Restarted", f"{vps.get('name')} has been restarted."))
            except Exception as e:
                await ctx.send(embed=create_error_embed("Restart Failed", str(e)))
        
        elif action == 'info':
            try:
                info = await execute_lxc(f"lxc info {container_name}")
                ip_info = await execute_lxc(f"lxc list {container_name} --format json")
                ip_data = json.loads(ip_info)[0]
                
                embed = create_embed(f"📊 {vps.get('name')} Info", f"Detailed information:", COLOR_INFO)
                embed.add_field(name="Container", value=f"`{container_name}`", inline=True)
                embed.add_field(name="Status", value=vps.get('status', 'unknown'), inline=True)
                embed.add_field(name="Plan", value=vps.get('plan', 'N/A'), inline=True)
                
                if 'state' in ip_data and 'network' in ip_data['state']:
                    for iface, net_info in ip_data['state']['network'].items():
                        if 'addresses' in net_info:
                            for addr in net_info['addresses']:
                                if addr['family'] == 'inet':
                                    embed.add_field(name=f"IP Address ({iface})", value=addr['address'], inline=True)
                
                embed.add_field(name="Specifications", 
                    value=f"**RAM:** {vps.get('ram', 'N/A')}\n"
                          f"**CPU:** {vps.get('cpu', 'N/A')} cores\n"
                          f"**Storage:** {vps.get('storage', 'N/A')}GB", inline=False)
                
                await ctx.send(embed=embed)
            except Exception as e:
                await ctx.send(embed=create_error_embed("Info Failed", str(e)))
        
        elif action == 'ssh':
            try:
                # Check if VPS is running
                if vps.get('status') != 'running':
                    await ctx.send(embed=create_warning_embed("VPS Not Running", f"Starting {container_name}..."))
                    await execute_lxc(f"lxc start {container_name}")
                    vps['status'] = 'running'
                    save_data()
                    await asyncio.sleep(3)
                
                processing_embed = create_embed("🔐 Setting up SSH Access", f"Fixing DNS and installing tmate on `{container_name}`...", COLOR_INFO)
                message = await ctx.send(embed=processing_embed)
                
                # Fix DNS first
                dns_fix_cmd = "echo 'nameserver 8.8.8.8' > /etc/resolv.conf && echo 'nameserver 1.1.1.1' >> /etc/resolv.conf"
                try:
                    await execute_lxc(f"lxc exec {container_name} -- bash -c '{dns_fix_cmd}'", timeout=10)
                except:
                    pass
                
                # Install tmate
                install_cmd = "apt-get update -qq && apt-get install -y tmate"
                await execute_lxc(f"lxc exec {container_name} -- bash -c '{install_cmd}'", timeout=180)
                
                processing_embed.description = "Generating SSH session..."
                await message.edit(embed=processing_embed)
                
                # Start tmate and get SSH link
                tmate_cmd = "tmate -F 2>&1 | grep -m1 'ssh session:' || tmate -F 2>&1 | head -20"
                result = await execute_lxc(f"lxc exec {container_name} -- bash -c '{tmate_cmd}'", timeout=30)
                
                # Extract SSH link
                ssh_link = None
                for line in result.split('\n'):
                    if 'ssh session:' in line.lower() or 'ssh ' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.startswith('ssh') and i + 1 < len(parts):
                                ssh_link = ' '.join(parts[i:])
                                break
                        if ssh_link:
                            break
                
                if not ssh_link:
                    # Alternative method - create a persistent tmate session
                    session_cmd = """
                    pkill tmate 2>/dev/null || true
                    rm -f /tmp/tmate.log
                    tmate -F -n tmate_session > /tmp/tmate.log 2>&1 &
                    sleep 5
                    cat /tmp/tmate.log | grep 'ssh session:' | head -1
                    """
                    result = await execute_lxc(f"lxc exec {container_name} -- bash -c \"{session_cmd}\"", timeout=30)
                    
                    for line in result.split('\n'):
                        if 'ssh ' in line:
                            ssh_link = line.strip()
                            break
                
                success_embed = create_success_embed(
                    "✅ SSH Access Ready!",
                    f"Your SSH session for `{container_name}` is ready!"
                )
                
                if ssh_link:
                    success_embed.add_field(
                        name="🔗 SSH Command",
                        value=f"```bash\n{ssh_link}\n```",
                        inline=False
                    )
                else:
                    success_embed.add_field(
                        name="🔗 Manual SSH Setup",
                        value=f"Tmate is installed. Connect to your VPS and run:\n```bash\ntmate -F\n```\nThen get the SSH link with:\n```bash\ntmate show-messages\n```",
                        inline=False
                    )
                
                success_embed.add_field(
                    name="📝 Instructions",
                    value="1. Copy the SSH command above\n"
                          "2. Paste it in your terminal\n"
                          "3. You'll have full SSH access to your VPS\n"
                          "4. Session will remain active until you close it",
                    inline=False
                )
                
                success_embed.add_field(
                    name="⚠️ Security Note",
                    value="• This session is temporary\n"
                          "• Anyone with the link can access your VPS\n"
                          "• Keep the link private\n"
                          "• Close the session when done",
                    inline=False
                )
                
                success_embed.add_field(
                    name="💡 Tip",
                    value="If tmate doesn't work, try manual SSH:\n"
                          "Use `.fix-internet` command first to fix DNS!",
                    inline=False
                )
                
                try:
                    await ctx.author.send(embed=success_embed)
                    await ctx.send(embed=create_success_embed(
                        "✅ SSH Link Sent!",
                        f"Check your DMs for SSH access to `{container_name}`!"
                    ))
                except discord.Forbidden:
                    await ctx.send(embed=create_error_embed(
                        "DM Failed",
                        "I couldn't send you a DM! Please enable DMs to receive SSH access."
                    ))
                
            except Exception as e:
                logger.exception(f"SSH setup failed: {e}")
                
                # Check if it's a DNS error
                error_msg = str(e)
                if 'resolving' in error_msg.lower() or 'fetch' in error_msg.lower():
                    await ctx.send(embed=create_error_embed(
                        "DNS/Internet Issue Detected",
                        f"Your VPS cannot connect to the internet.\n\n"
                        f"**Quick Fix:**\n"
                        f"1. Use `.fix-internet` command for detailed guide\n"
                        f"2. Or manually run in your VPS:\n"
                        f"```bash\n"
                        f"echo 'nameserver 8.8.8.8' > /etc/resolv.conf\n"
                        f"echo 'nameserver 1.1.1.1' >> /etc/resolv.conf\n"
                        f"apt-get update\n"
                        f"apt-get install -y tmate\n"
                        f"tmate -F\n"
                        f"```"
                    ))
                else:
                    await ctx.send(embed=create_error_embed(
                        "SSH Setup Failed",
                        f"Failed to setup SSH access: {str(e)[:100]}\n\n"
                        f"Try installing tmate manually:\n"
                        f"```bash\n"
                        f"apt-get update && apt-get install -y tmate\n"
                        f"tmate -F\n"
                        f"```"
                    ))
        
        elif action == 'delete':
            confirm_embed = create_warning_embed("⚠️ Delete VPS", 
                f"This will permanently delete {vps.get('name')} (`{container_name}`).\n"
                f"This action cannot be undone!\n\n"
                f"Type `CONFIRM DELETE` to proceed.")
            
            await ctx.send(embed=confirm_embed)
            
            try:
                confirm_msg = await bot.wait_for('message', timeout=30.0, check=check)
                if confirm_msg.content.upper() == 'CONFIRM DELETE':
                    try:
                        await execute_lxc(f"lxc delete {container_name} --force")
                        vps_data[user_id].pop(vps_num)
                        if not vps_data[user_id]:
                            del vps_data[user_id]
                        save_data()
                        await ctx.send(embed=create_success_embed("VPS Deleted", f"{vps.get('name')} has been permanently deleted."))
                    except Exception as e:
                        await ctx.send(embed=create_error_embed("Delete Failed", str(e)))
                else:
                    await ctx.send(embed=create_info_embed("Deletion Cancelled", "VPS was not deleted."))
            except asyncio.TimeoutError:
                await ctx.send(embed=create_info_embed("Timeout", "Deletion cancelled due to timeout."))
        
        else:
            await ctx.send(embed=create_error_embed("Invalid Action", 
                "Available actions: start, stop, restart, info, delete"))
            
    except asyncio.TimeoutError:
        await ctx.send(embed=create_error_embed("Timeout", "You took too long to respond. Please try again."))

@bot.command(name='credits')
async def show_credits(ctx):
    user_id = str(ctx.author.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
        save_data()
    
    embed = create_embed("💰 Credit Balance", f"Your account balance:", COLOR_PRIMARY)
    embed.add_field(name="Available Credits", value=f"{user_data[user_id]['credits']} credits", inline=False)
    embed.add_field(name="Need More?", value="Use .buyc to view payment methods or chat to earn more!", inline=False)
    await ctx.send(embed=embed)

# ========== TAILSCALE COMMANDS ==========
@bot.command(name='tailscale-me')
async def tailscale_me(ctx):
    user_id = str(ctx.author.id)
    
    if user_id not in vps_data or not vps_data[user_id]:
        await ctx.send(embed=create_error_embed("No VPS Found", "You don't have any VPS to set up Tailscale on."))
        return
    
    user_vps_list = vps_data[user_id]
    
    embed = create_embed("🔗 Tailscale Setup", "Select which VPS to install Tailscale on:", COLOR_INFO)
    
    for i, vps in enumerate(user_vps_list, 1):
        status_emoji = "🟢" if vps.get('status') == 'running' else "🔴"
        embed.add_field(
            name=f"#{i} {status_emoji} {vps.get('name', 'Unnamed')}",
            value=f"Container: `{vps['container_name']}`\nStatus: {vps.get('status', 'unknown')}",
            inline=False
        )
    
    embed.add_field(
        name="Instructions",
        value="Reply with the number of the VPS you want to install Tailscale on.\nType `cancel` to cancel.",
        inline=False
    )
    
    await ctx.send(embed=embed)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    try:
        msg = await bot.wait_for('message', timeout=60.0, check=check)
        
        if msg.content.lower() == 'cancel':
            await ctx.send(embed=create_info_embed("Cancelled", "Tailscale setup cancelled."))
            return
        
        try:
            selection = int(msg.content) - 1
            if selection < 0 or selection >= len(user_vps_list):
                await ctx.send(embed=create_error_embed("Invalid Selection", f"Please choose a number between 1 and {len(user_vps_list)}"))
                return
        except ValueError:
            await ctx.send(embed=create_error_embed("Invalid Input", "Please enter a valid number."))
            return
        
        selected_vps = user_vps_list[selection]
        container_name = selected_vps['container_name']
        
        if selected_vps.get('status') != 'running':
            await ctx.send(embed=create_warning_embed("VPS Not Running", f"Starting {container_name}..."))
            try:
                await execute_lxc(f"lxc start {container_name}")
                selected_vps['status'] = 'running'
                save_data()
            except Exception as e:
                await ctx.send(embed=create_error_embed("Failed to Start", f"Could not start container: {str(e)}"))
                return
        
        processing_embed = create_embed("⚙️ Installing Tailscale", f"Setting up Tailscale on `{container_name}`...", COLOR_INFO)
        processing_embed.add_field(name="Status", value="Installing dependencies...", inline=False)
        message = await ctx.send(embed=processing_embed)
        
        try:
            update_cmd = "apt-get update && apt-get install -y curl gnupg lsb-release"
            await execute_lxc(f"lxc exec {container_name} -- bash -c '{update_cmd}'", timeout=120)
            
            install_cmd = "curl -fsSL https://tailscale.com/install.sh | sh"
            await execute_lxc(f"lxc exec {container_name} -- bash -c '{install_cmd}'", timeout=180)
            
            processing_embed.set_field_at(0, name="Status", value="✅ Tailscale installed successfully!\nGenerating auth link...", inline=False)
            await message.edit(embed=processing_embed)
            
            tailscale_cmd = "tailscale up --auth-key tskey-auth-kw2PpK3CNTRL-JCuBUu5PtK6F8dpf71VqvjTVLwZqZ9qG && tailscale ip -4"
            result = await execute_lxc(f"lxc exec {container_name} -- bash -c '{tailscale_cmd}'", timeout=60)
            
            ip_cmd = "tailscale ip -4 2>/dev/null || echo 'Not connected'"
            ip_result = await execute_lxc(f"lxc exec {container_name} -- bash -c '{ip_cmd}'")
            
            success_embed = create_success_embed(
                "✅ Tailscale Setup Complete!",
                f"Tailscale has been successfully installed on your VPS `{container_name}`"
            )
            success_embed.add_field(name="Container", value=f"`{container_name}`", inline=True)
            
            if ip_result and ip_result != "Not connected":
                success_embed.add_field(name="Tailscale IP", value=f"`{ip_result.strip()}`", inline=True)
            
            success_embed.add_field(
                name="Next Steps",
                value="1. Install Tailscale on your devices from https://tailscale.com/download\n"
                      "2. Your VPS will automatically appear in your Tailscale network\n"
                      "3. Connect using the Tailscale IP above",
                inline=False
            )
            
            success_embed.add_field(
                name="Useful Commands",
                value="```bash\n"
                      "# Check Tailscale status\n"
                      "tailscale status\n\n"
                      "# Get Tailscale IP\n"
                      "tailscale ip -4\n\n"
                      "# View network info\n"
                      "tailscale netcheck\n"
                      "```",
                inline=False
            )
            
            try:
                await ctx.author.send(embed=success_embed)
                await ctx.send(embed=create_success_embed(
                    "✅ Tailscale Link Sent!",
                    f"Check your DMs for the Tailscale setup details for `{container_name}`!"
                ))
            except discord.Forbidden:
                await ctx.send(embed=create_error_embed(
                    "DM Failed", 
                    "I couldn't send you a DM! Please enable DMs to receive your Tailscale information."
                ))
            
        except Exception as e:
            logger.exception(f"Tailscale installation failed: {e}")
            await ctx.send(embed=create_error_embed(
                "Installation Failed",
                f"Failed to install Tailscale: {str(e)[:100]}"
            ))
            
    except asyncio.TimeoutError:
        await ctx.send(embed=create_error_embed("Timeout", "You took too long to respond. Please try again."))

@bot.command(name='tailscale-status')
async def tailscale_status(ctx):
    user_id = str(ctx.author.id)
    
    if user_id not in vps_data or not vps_data[user_id]:
        await ctx.send(embed=create_error_embed("No VPS Found", "You don't have any VPS."))
        return
    
    embed = create_embed("📡 Tailscale Status", "Tailscale status on your VPS:", COLOR_INFO)
    
    for vps in vps_data[user_id]:
        container_name = vps['container_name']
        vps_name = vps.get('name', 'Unnamed')
        
        try:
            check_cmd = "which tailscale 2>/dev/null && echo 'installed' || echo 'not_installed'"
            result = await execute_lxc(f"lxc exec {container_name} -- bash -c '{check_cmd}'", timeout=30)
            
            if "installed" in result:
                status_cmd = "tailscale status --json 2>/dev/null || echo 'not_running'"
                status_result = await execute_lxc(f"lxc exec {container_name} -- bash -c '{status_cmd}'", timeout=30)
                
                if "not_running" not in status_result:
                    try:
                        status_data = json.loads(status_result)
                        status = "🟢 Connected"
                        ip = status_data.get('Self', {}).get('TailscaleIPs', ['N/A'])[0]
                    except:
                        status = "🟡 Running"
                        ip = "Unknown"
                else:
                    status = "🔴 Not Running"
                    ip = "N/A"
                    
                embed.add_field(
                    name=f"🔗 {vps_name}",
                    value=f"Status: {status}\nIP: `{ip}`\nContainer: `{container_name}`",
                    inline=True
                )
            else:
                embed.add_field(
                    name=f"❌ {vps_name}",
                    value=f"Tailscale not installed\nContainer: `{container_name}`",
                    inline=True
                )
                
        except Exception as e:
            logger.error(f"Error checking Tailscale status for {container_name}: {e}")
            embed.add_field(
                name=f"⚠️ {vps_name}",
                value=f"Error checking status\nContainer: `{container_name}`",
                inline=True
            )
    
    await ctx.send(embed=embed)

# ========== ADMIN COMMANDS ==========
@bot.command(name='add-admin')
@is_main_admin()
async def add_admin(ctx, member: discord.Member = None):
    """Add a user as admin (Main admin only)"""
    if not member:
        await ctx.send(embed=create_error_embed(
            "Missing User",
            "Usage: `.add-admin @user`\nExample: `.add-admin @username`"
        ))
        return
    
    user_id = str(member.id)
    
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Already Admin", "This user is the main admin!"))
        return
    
    if user_id in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Already Admin", f"{member.mention} is already an admin!"))
        return
    
    if "admins" not in admin_data:
        admin_data["admins"] = [str(MAIN_ADMIN_ID)]
    
    admin_data["admins"].append(user_id)
    save_data()
    
    embed = create_success_embed("Admin Added", f"{member.mention} has been added as an admin!")
    embed.add_field(name="User", value=member.mention, inline=True)
    embed.add_field(name="User ID", value=user_id, inline=True)
    embed.add_field(name="Total Admins", value=len(admin_data["admins"]), inline=True)
    
    await ctx.send(embed=embed)
    
    try:
        dm_embed = create_success_embed(
            "🎉 Admin Role Granted!",
            f"You have been granted admin privileges in **{ctx.guild.name}**!"
        )
        dm_embed.add_field(
            name="Admin Commands Available",
            value="• .stop-all\n• .start-all\n• .suspend-all\n• .create @user [plan]\n• .adminc @user amount\n• .serverstats",
            inline=False
        )
        await member.send(embed=dm_embed)
    except discord.Forbidden:
        pass

@bot.command(name='rm-admin')
@is_main_admin()
async def remove_admin(ctx, member: discord.Member = None):
    """Remove a user from admin (Main admin only)"""
    if not member:
        await ctx.send(embed=create_error_embed(
            "Missing User",
            "Usage: `.rm-admin @user`\nExample: `.rm-admin @username`"
        ))
        return
    
    user_id = str(member.id)
    
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Cannot Remove", "You cannot remove the main admin!"))
        return
    
    if user_id not in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Not Admin", f"{member.mention} is not an admin!"))
        return
    
    admin_data["admins"].remove(user_id)
    save_data()
    
    embed = create_success_embed("Admin Removed", f"{member.mention} has been removed from admins!")
    embed.add_field(name="User", value=member.mention, inline=True)
    embed.add_field(name="User ID", value=user_id, inline=True)
    embed.add_field(name="Remaining Admins", value=len(admin_data["admins"]), inline=True)
    
    await ctx.send(embed=embed)
    
    try:
        dm_embed = create_info_embed(
            "Admin Role Revoked",
            f"Your admin privileges in **{ctx.guild.name}** have been revoked."
        )
        await member.send(embed=dm_embed)
    except discord.Forbidden:
        pass

@bot.command(name='list-admins')
@is_admin()
async def list_admins(ctx):
    """List all admins"""
    embed = create_embed("👑 Admin List", "Current server admins:", COLOR_INFO)
    
    admin_list = []
    for admin_id in admin_data.get("admins", []):
        try:
            user = await bot.fetch_user(int(admin_id))
            is_main = " 👑" if admin_id == str(MAIN_ADMIN_ID) else ""
            admin_list.append(f"• {user.name}{is_main} (`{admin_id}`)")
        except:
            admin_list.append(f"• Unknown User (`{admin_id}`)")
    
    if admin_list:
        embed.add_field(name="Admins", value="\n".join(admin_list), inline=False)
    else:
        embed.add_field(name="Admins", value="No admins found", inline=False)
    
    embed.add_field(name="Total", value=f"{len(admin_data.get('admins', []))} admin(s)", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='game-settings')
@is_main_admin()
async def game_settings_cmd(ctx, setting: str = None, value: int = None):
    """Configure game rewards (Main admin only)
    Usage: .game-settings [setting] [value]
    Example: .game-settings tic_tac_toe_reward 100
    """
    if not setting:
        embed = create_embed("🎮 Game Settings", "Current game configuration:", COLOR_INFO)
        embed.add_field(
            name="Tic-Tac-Toe Reward",
            value=f"{game_settings.get('tic_tac_toe_reward', TIC_TAC_TOE_REWARD)} credits",
            inline=True
        )
        embed.add_field(
            name="Rock Paper Scissors Reward",
            value=f"{game_settings.get('rock_paper_scissors_reward', ROCK_PAPER_SCISSORS_REWARD)} credits",
            inline=True
        )
        embed.add_field(
            name="Number Guess Reward",
            value=f"{game_settings.get('number_guess_reward', NUMBER_GUESS_REWARD)} credits",
            inline=True
        )
        embed.add_field(
            name="Trivia Reward",
            value=f"{game_settings.get('trivia_reward', TRIVIA_REWARD)} credits",
            inline=True
        )
        embed.add_field(
            name="How to Update",
            value="`.game-settings [setting] [amount]`\n\n"
                  "**Available settings:**\n"
                  "• tic_tac_toe_reward\n"
                  "• rock_paper_scissors_reward\n"
                  "• number_guess_reward\n"
                  "• trivia_reward",
            inline=False
        )
        await ctx.send(embed=embed)
        return
    
    valid_settings = ["tic_tac_toe_reward", "rock_paper_scissors_reward", "number_guess_reward", "trivia_reward"]
    
    if setting not in valid_settings:
        await ctx.send(embed=create_error_embed(
            "Invalid Setting",
            f"Available settings:\n" + "\n".join([f"• {s}" for s in valid_settings])
        ))
        return
    
    if value is None:
        await ctx.send(embed=create_error_embed("Missing Value", f"Usage: `.game-settings {setting} [amount]`"))
        return
    
    if value < 0:
        await ctx.send(embed=create_error_embed("Invalid Value", "Reward must be 0 or greater!"))
        return
    
    old_value = game_settings.get(setting, 0)
    game_settings[setting] = value
    save_data()
    
    setting_names = {
        "tic_tac_toe_reward": "Tic-Tac-Toe Reward",
        "rock_paper_scissors_reward": "Rock Paper Scissors Reward",
        "number_guess_reward": "Number Guess Reward",
        "trivia_reward": "Trivia Reward"
    }
    
    embed = create_success_embed("Settings Updated", "Game settings have been updated!")
    embed.add_field(name="Setting", value=setting_names.get(setting, setting), inline=True)
    embed.add_field(name="Old Value", value=f"{old_value} credits", inline=True)
    embed.add_field(name="New Value", value=f"{value} credits", inline=True)
    
    await ctx.send(embed=embed)

@bot.command(name='stop-all')
@is_admin()
async def stop_all(ctx):
    confirm_embed = create_warning_embed("⚠️ Stop All VPS", "This will stop ALL running VPS. Continue?")
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="✅ Confirm", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "lxc", "stop", "--all", "--force",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                
                stopped_count = 0
                for user_id, vps_list in vps_data.items():
                    for vps in vps_list:
                        if vps.get('status') == 'running':
                            vps['status'] = 'stopped'
                            stopped_count += 1
                save_data()
                
                await interaction.followup.send(embed=create_success_embed("All VPS Stopped", f"Successfully stopped {stopped_count} VPS"))
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Error", str(e)))
        
        @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Cancelled", "Operation cancelled"), view=None)
    
    await ctx.send(embed=confirm_embed, view=ConfirmView())

@bot.command(name='start-all')
@is_admin()
async def start_all(ctx):
    await ctx.send(embed=create_info_embed("Starting All VPS", "Starting all containers..."))
    
    started_count = 0
    failed = []
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            container_name = vps['container_name']
            try:
                await execute_lxc(f"lxc start {container_name}")
                vps['status'] = 'running'
                started_count += 1
            except Exception as e:
                failed.append(f"{container_name}: {str(e)[:50]}")
                logger.error(f"Failed to start {container_name}: {e}")
    
    save_data()
    
    embed = create_success_embed("Start All Complete", f"Successfully started {started_count} VPS")
    if failed:
        failures = "\n".join(failed[:5])
        if len(failed) > 5:
            failures += f"\n... and {len(failed) - 5} more"
        embed.add_field(name="⚠️ Failed", value=f"```{failures}```", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='suspend-all')
@is_admin()
async def suspend_all(ctx):
    confirm_embed = create_warning_embed("⚠️ Suspend All VPS", "This will suspend (freeze) ALL VPS. Continue?")
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="✅ Confirm", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            suspended_count = 0
            failed = []
            for user_id, vps_list in vps_data.items():
                for vps in vps_list:
                    container_name = vps['container_name']
                    try:
                        await execute_lxc(f"lxc pause {container_name}")
                        vps['status'] = 'suspended'
                        suspended_count += 1
                    except Exception as e:
                        failed.append(f"{container_name}: {str(e)[:50]}")
            save_data()
            
            embed = create_success_embed("All VPS Suspended", f"Successfully suspended {suspended_count} VPS")
            if failed:
                failures = "\n".join(failed[:5])
                if len(failed) > 5:
                    failures += f"\n... and {len(failed) - 5} more"
                embed.add_field(name="⚠️ Failed", value=f"```{failures}```", inline=False)
            await interaction.followup.send(embed=embed)
        
        @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Cancelled", "Operation cancelled"), view=None)
    
    await ctx.send(embed=confirm_embed, view=ConfirmView())

@bot.command(name='unsuspend-all')
@is_admin()
async def unsuspend_all(ctx):
    confirm_embed = create_warning_embed("⚠️ Unsuspend All VPS", "This will unsuspend (unfreeze) ALL suspended VPS. Continue?")
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)
        
        @discord.ui.button(label="✅ Confirm", style=discord.ButtonStyle.success)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            unsuspended_count = 0
            failed = []
            for user_id, vps_list in vps_data.items():
                for vps in vps_list:
                    container_name = vps['container_name']
                    if vps.get('status') == 'suspended':
                        try:
                            await execute_lxc(f"lxc start {container_name}")
                            vps['status'] = 'running'
                            unsuspended_count += 1
                        except Exception as e:
                            failed.append(f"{container_name}: {str(e)[:50]}")
            save_data()
            
            embed = create_success_embed("All VPS Unsuspended", f"Successfully unsuspended {unsuspended_count} VPS")
            if failed:
                failures = "\n".join(failed[:5])
                if len(failed) > 5:
                    failures += f"\n... and {len(failed) - 5} more"
                embed.add_field(name="⚠️ Failed", value=f"```{failures}```", inline=False)
            await interaction.followup.send(embed=embed)
        
        @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Cancelled", "Operation cancelled"), view=None)
    
    await ctx.send(embed=confirm_embed, view=ConfirmView())

@bot.command(name='delete-all')
@is_admin()
async def delete_all(ctx):
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    
    confirm_embed = create_warning_embed(
        "🚨 DELETE ALL VPS - CRITICAL WARNING",
        f"⚠️ **THIS WILL PERMANENTLY DELETE ALL {total_vps} VPS!**\n\n"
        "This action is **IRREVERSIBLE** and will:\n"
        "• Delete all containers\n"
        "• Remove all user VPS data\n"
        "• Cannot be undone\n\n"
        "**Type 'DELETE ALL VPS' to confirm this dangerous action.**"
    )
    
    await ctx.send(embed=confirm_embed)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    try:
        msg = await bot.wait_for('message', timeout=30.0, check=check)
        
        if msg.content != 'DELETE ALL VPS':
            await ctx.send(embed=create_info_embed("Operation Cancelled", "Deletion aborted. VPS are safe."))
            return
        
        # Second confirmation
        final_confirm = create_warning_embed(
            "🚨 FINAL CONFIRMATION",
            f"You are about to delete **{total_vps} VPS containers**.\n\n"
            "This is your last chance to cancel.\n\n"
            "Click Confirm to proceed with deletion."
        )
        
        class FinalConfirmView(discord.ui.View):
            def __init__(self):
                super().__init__(timeout=30)
            
            @discord.ui.button(label="🗑️ CONFIRM DELETE ALL", style=discord.ButtonStyle.danger)
            async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
                if interaction.user.id != ctx.author.id:
                    await interaction.response.send_message("This is not your action!", ephemeral=True)
                    return
                
                await interaction.response.defer()
                
                progress_embed = create_info_embed("Deleting All VPS", "Please wait, deleting all containers...")
                await interaction.followup.send(embed=progress_embed)
                
                deleted_count = 0
                failed = []
                
                for user_id, vps_list in list(vps_data.items()):
                    for vps in list(vps_list):
                        container_name = vps['container_name']
                        try:
                            await execute_lxc(f"lxc delete {container_name} --force")
                            deleted_count += 1
                        except Exception as e:
                            failed.append(f"{container_name}: {str(e)[:50]}")
                            logger.error(f"Failed to delete {container_name}: {e}")
                
                # Clear all VPS data
                vps_data.clear()
                save_data()
                
                result_embed = create_success_embed(
                    "All VPS Deleted",
                    f"Successfully deleted {deleted_count} VPS containers.\n"
                    f"All VPS data has been cleared."
                )
                
                if failed:
                    failures = "\n".join(failed[:5])
                    if len(failed) > 5:
                        failures += f"\n... and {len(failed) - 5} more"
                    result_embed.add_field(name="⚠️ Failed to Delete", value=f"```{failures}```", inline=False)
                
                await interaction.followup.send(embed=result_embed)
            
            @discord.ui.button(label="❌ Cancel", style=discord.ButtonStyle.secondary)
            async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
                if interaction.user.id != ctx.author.id:
                    await interaction.response.send_message("This is not your action!", ephemeral=True)
                    return
                
                await interaction.response.edit_message(
                    embed=create_info_embed("Operation Cancelled", "VPS deletion aborted. All VPS are safe."),
                    view=None
                )
        
        await ctx.send(embed=final_confirm, view=FinalConfirmView())
        
    except asyncio.TimeoutError:
        await ctx.send(embed=create_info_embed("Timeout", "Operation cancelled due to timeout. VPS are safe."))


@bot.command(name='create')
@is_admin()
async def admin_create(ctx, member: discord.Member = None, plan_name: str = "Starter"):
    """Create VPS for a user (Admin only)
    Usage: .create @user [plan_name]
    Example: .create @user Basic
    """
    if not member:
        await ctx.send(embed=create_error_embed(
            "Missing User", 
            "Please mention a user: `.create @username [plan]`\nExample: `.create @user Basic`"
        ))
        return
    
    plan_name = plan_name.capitalize()
    if plan_name not in PLANS:
        await ctx.send(embed=create_error_embed("Invalid Plan", 
            f"Available plans: {', '.join(PLANS.keys())}\nExample: `.create {member.mention} Basic`"))
        return
    
    user_id = str(member.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
    
    plan_details = PLANS[plan_name]
    
    container_name = generate_container_name()
    try:
        await core_create_container(
            container_name=container_name,
            ram_gb=int(plan_details['ram'].replace('GB', '')),
            cpu=int(plan_details['cpu']),
            storage_gb=plan_details['storage']
        )
        
        if user_id not in vps_data:
            vps_data[user_id] = []
        
        vps_info = {
            'name': f"{plan_name} VPS",
            'container_name': container_name,
            'plan': plan_name,
            'ram': plan_details['ram'],
            'cpu': plan_details['cpu'],
            'storage': plan_details['storage'],
            'status': 'running',
            'created_at': datetime.now().isoformat()
        }
        
        vps_data[user_id].append(vps_info)
        save_data()
        
        try:
            vps_role = await get_or_create_vps_role(ctx.guild)
            if vps_role:
                await member.add_roles(vps_role)
        except:
            pass
        
        success_embed = create_success_embed(
            "✅ VPS Created Successfully!",
            f"Created {plan_name} VPS for {member.mention}"
        )
        success_embed.add_field(name="Container Name", value=f"`{container_name}`", inline=False)
        success_embed.add_field(name="Specifications", 
            value=f"**RAM:** {plan_details['ram']}\n"
                  f"**CPU:** {plan_details['cpu']} cores\n"
                  f"**Storage:** {plan_details['storage']}GB", inline=False)
        
        await ctx.send(embed=success_embed)
        
    except Exception as e:
        logger.error(f"Admin VPS creation failed: {e}")
        await ctx.send(embed=create_error_embed(
            "Creation Failed",
            f"Failed to create VPS: {str(e)[:100]}"
        ))

@bot.command(name='adminc')
@is_admin()
async def admin_credits(ctx, member: discord.Member = None, amount: int = None):
    """Add credits to a user (Admin only)"""
    if not member or amount is None:
        await ctx.send(embed=create_error_embed("Usage", "`.adminc @user amount`\nExample: `.adminc @user 1000`"))
        return
    
    user_id = str(member.id)
    if user_id not in user_data:
        user_data[user_id] = {"credits": 0, "messages": 0}
    
    user_data[user_id]['credits'] += amount
    save_data()
    
    embed = create_success_embed("Credits Added", f"Added {amount} credits to {member.mention}")
    embed.add_field(name="New Balance", value=f"{user_data[user_id]['credits']} credits", inline=False)
    await ctx.send(embed=embed)

@bot.command(name='serverstats')
@is_admin()
async def server_stats(ctx):
    """Show server statistics (Admin only)"""
    try:
        containers_info = await execute_lxc("lxc list --format json")
        containers = json.loads(containers_info)
        
        storage_info = await execute_lxc("lxc storage list --format json")
        storage = json.loads(storage_info)
        
        total_vps = sum(len(vps_list) for vps_list in vps_data.values())
        active_users = len(vps_data)
        
        embed = create_embed("📊 Server Statistics", "Current server status:", COLOR_INFO)
        
        embed.add_field(name="🏗️ Containers", value=f"**Total:** {len(containers)}\n**Running:** {len([c for c in containers if c.get('status') == 'Running'])}", inline=True)
        embed.add_field(name="👥 Users", value=f"**Active Users:** {active_users}\n**Total VPS:** {total_vps}", inline=True)
        embed.add_field(name="💾 Storage", value=f"**Pools:** {len(storage)}\n**Default:** {DEFAULT_STORAGE_POOL}", inline=True)
        
        cpu_usage = get_cpu_usage()
        cpu_status = "🟢 Low" if cpu_usage < 50 else "🟡 Medium" if cpu_usage < 80 else "🔴 High"
        embed.add_field(name="⚡ CPU Usage", value=f"**{cpu_usage:.1f}%**\n**Status:** {cpu_status}", inline=True)
        
        try:
            mem_info = subprocess.run(['free', '-m'], capture_output=True, text=True)
            lines = mem_info.stdout.split('\n')
            if len(lines) > 1:
                mem_data = lines[1].split()
                total_mem = int(mem_data[1])
                used_mem = int(mem_data[2])
                mem_percent = (used_mem / total_mem) * 100
                embed.add_field(name="🧠 Memory", value=f"**Used:** {used_mem}MB/{total_mem}MB\n**({mem_percent:.1f}%)**", inline=True)
        except:
            pass
        
        embed.add_field(name="📈 Activity", 
            value=f"**Total Users:** {len(user_data)}\n**Messages:** {sum(user.get('messages', 0) for user in user_data.values())}\n**Credits:** {sum(user.get('credits', 0) for user in user_data.values())}", 
            inline=True)
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send(embed=create_error_embed("Stats Error", str(e)))

@bot.command(name='help')
async def show_help(ctx):
    user_id = str(ctx.author.id)
    is_user_admin = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    
    embed = create_embed(f"📚 {BOT_NAME} Commands", "All available commands", COLOR_PRIMARY)
    
    user_cmds = (
        "**.ping** - Check bot latency\n"
        "**.messages** - View message stats & rewards\n"
        "**.credits** - Check credit balance\n"
        "**.plans** - View VPS plans & pricing\n"
        "**.buyc** - Get payment methods\n"
        "**.buywc [plan]** - Purchase VPS with credits\n"
        "**.manage** - Manage your VPS\n"
        "**.fix-internet** - VPS internet optimization guide\n"
        "**.tailscale-me** - Install Tailscale on your VPS\n"
        "**.tailscale-status** - Check Tailscale status\n"
        "**.trial** - Get FREE 3-day trial VPS (2GB RAM, 1 CPU)\n"
        "**.play-tic-tac-toe @user** - Play tic-tac-toe game\n"
        "**.play-rps @user** - Play rock paper scissors\n"
        "**.play-guess** - Play number guessing game\n"
        "**.play-trivia** - Play trivia quiz"
    )
    embed.add_field(name="👤 User Commands", value=user_cmds, inline=False)
    
    if is_user_admin:
        admin_cmds = (
            "**.stop-all** - Stop all VPS\n"
            "**.start-all** - Start all VPS\n"
            "**.suspend-all** - Suspend all VPS\n"
            "**.unsuspend-all** - Unsuspend all VPS\n"
            "**.delete-all** - Delete all VPS (DANGEROUS)\n"
            "**.create @user [plan]** - Create VPS\n"
            "**.adminc @user amount** - Add credits\n"
            "**.serverstats** - View server statistics\n"
            "**.list-admins** - List all admins"
        )
        embed.add_field(name="🛡️ Admin Commands", value=admin_cmds, inline=False)
        
        if user_id == str(MAIN_ADMIN_ID):
            main_admin_cmds = (
                "**.add-admin @user** - Add new admin\n"
                "**.rm-admin @user** - Remove admin\n"
                "**.game-settings [setting] [value]** - Configure game rewards"
            )
            embed.add_field(name="👑 Main Admin Commands", value=main_admin_cmds, inline=False)
    
    embed.add_field(name="💬 Message Rewards", 
                    value=f"Earn **{MESSAGE_REWARD} credits** every **{MESSAGE_THRESHOLD} messages**!\nUse .messages to track your progress.", 
                    inline=False)
    
    embed.add_field(name="🎮 Game Rewards",
                    value=f"**Tic-Tac-Toe:** {game_settings.get('tic_tac_toe_reward', TIC_TAC_TOE_REWARD)} credits\n"
                          f"**Rock Paper Scissors:** {game_settings.get('rock_paper_scissors_reward', ROCK_PAPER_SCISSORS_REWARD)} credits\n"
                          f"**Number Guess:** {game_settings.get('number_guess_reward', NUMBER_GUESS_REWARD)} credits\n"
                          f"**Trivia Quiz:** {game_settings.get('trivia_reward', TRIVIA_REWARD)} credits",
                    inline=False)
    
    embed.add_field(name="🎁 Free Trial",
                    value=f"Get a **FREE** trial VPS for {TRIAL_VPS_DURATION_DAYS} days!\nUse `.trial` to claim!",
                    inline=False)
    
    await ctx.send(embed=embed)

# ========== EVENT HANDLERS ==========
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"{BOT_NAME} | .help"))
    logger.info("Bot is ready!")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing Argument", "Check .help for usage"))
    elif isinstance(error, commands.CheckFailure):
        pass
    else:
        logger.exception(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("Error", f"An error occurred: {str(error)[:100]}"))

if __name__ == "__main__":
    token = DISCORD_BOT_TOKEN or os.getenv('DISCORD_BOT_TOKEN') or ''
    if not token:
        logger.error("No token provided!")
        raise SystemExit("No token!")
    bot.run(token)