"""
AGH Service BOT (t.me/CtffTest_bot.):- 
========================================================

# NOTE: This repository is a work in progress. 
# Please check back regularly for the latest updates and improvements.
#
# ⚠️ Reminder: Temporary development configuration/environment files 
# should not be kept in the repo and its Branches. Ensure they are deleted to prevent leakage of sensitve information.

OVERVIEW
- The bot NEVER discloses sensitive information.
- It returns a base64-encoded POINTER (e.g., a URL you control) only if the user proves
  knowledge of a secret via HMAC, bound to a one-time nonce and the sender’s Telegram user id.
  

PLAYER FLOW (COMMAND-BASED)
1) /challenge      → bot returns a one-time nonce (valid for NONCE_TTL seconds)
2) Compute HMAC_SHA256 over the ASCII message: f"{nonce}:{telegram_user_id}"
   - Key is provided elsewhere in the challenge (binary key via env; see below)
   - Output must be a 64-char lowercase hex string
3) /redeem <hmac_hex>         → validates against the active nonce for *your* id
   (alt) /redeem <id> <hmac_hex>  → optional form; id must match your Telegram id

RESPONSES
- Valid /redeem → base64(FLAG_2_URL)
- “flag”/“CTF{” in a normal message → refusal
- Everything else → stock line: “new language model will be available in the future to aswer your queries”

ENV (configure on host: Read from the enviroment file )
- BOT_TOKEN       : Telegram bot token
- FLAG_2_URL      : Pointer string to encode and return
- NONCE_TTL       : Nonce validity (seconds; default 600)
- HMAC KEY (BINARY; precedence)
1) HMAC_KEY_B64   : Base64-encoded random bytes (recommended: 32 bytes)


TODO:

SWITCH to AI


"""

import os, time, hmac, hashlib, base64, secrets, binascii, re
from typing import Optional
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ── Config ─────────────────────────────────────────────────────────────────────
load_dotenv()  # local dev only; on prod use real env vars

BOT_TOKEN      = os.environ["BOT_TOKEN"]
FLAG2_POINTER  = os.environ.get("FLAG_2_URL", "https://example.com/next.txt")
NONCE_TTL      = int(os.environ.get("NONCE_TTL", "600"))

REFUSAL_TEXT = "I’m sorry, but I can’t share information related to flags."
GENERIC_TEXT = "new language model will be available in the future to aswer your queries"

# ── HMAC key loading (binary) ─────────────────────────────────────────────────
def _load_hmac_key_bytes() -> bytes:
    b64 = os.environ.get("HMAC_KEY_B64")
    if b64:
        try:
            return base64.b64decode(b64.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("HMAC_KEY_B64 is not valid Base64")

    hx = os.environ.get("HMAC_KEY_HEX")
    if hx:
        try:
            return bytes.fromhex(hx.strip())
        except ValueError:
            raise ValueError("HMAC_KEY_HEX is not valid hex")

    raw = os.environ.get("HMAC_KEY")
    if raw:
        return raw.encode("utf-8")

    raise ValueError("No HMAC key provided; set HMAC_KEY_B64 or HMAC_KEY_HEX (preferred).")

HMAC_KEY_BYTES = _load_hmac_key_bytes()
if len(HMAC_KEY_BYTES) < 16:
    raise ValueError("HMAC key too short; provide at least 16 random bytes (32 recommended).")

# ── Nonce store ────────────────────────────────────────────────────────────────
# { user_id: {nonce:str, exp:int} }
pending = {}

def issue_nonce(user_id: int) -> str:
    n = secrets.token_hex(16)  # 16 bytes → 32 hex chars
    pending[user_id] = {"nonce": n, "exp": int(time.time()) + NONCE_TTL}
    return n


def compute_expected_hmac(nonce: str, user_id: int) -> str:
    msg = f"{nonce}:{user_id}".encode()
    return hmac.new(HMAC_KEY_BYTES, msg, hashlib.sha256).hexdigest()

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.run_polling(allowed_updates=Update.ALL_TYPES)  # polling is easiest to host anywhere

if __name__ == "__main__":
    main()
