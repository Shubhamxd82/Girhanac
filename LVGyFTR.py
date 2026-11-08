#SCRIPT BY LootVerse @lootverseoffers
"""
gyftr_login.py — interactive Gyftr OTP login + Diwali 2026 campaign play.

Flow:
    login/reuse session -> fetch profile -> ask points -> play -> show epay result

Next launch (if numbersession.json has entries):
    1) Login with a new number
    2) Choose a saved session from the list

Requires: requests, cryptography
    pip install requests cryptography
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
API_BASE       = "https://api.gyftr.com"
CAMPAIGN       = "DIWALI2026"
CAMPAIGN_PATH  = "diwali2026"
SESSION_FILE   = "numbersession.json"

PASSPHRASE     = "d909dg78609e47ak47diy4cf87t90c4a"
PLAY_PATH      = f"/gyftrapi/api/v1/caimpaign/{CAMPAIGN_PATH}"

# User-selectable points range
MIN_POINTS     = 1
MAX_POINTS     = 150

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": "https://www.gyftr.com",
    "referer": "https://www.gyftr.com/",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    ),
}

AUTH_HEADERS = {
    "device": "desktop",
    "platform": "web",
    "cache-control": "no-cache, no-store, must-revalidate",
    "pragma": "no-cache",
}


# --------------------------------------------------------------------------- #
# Crypto
# --------------------------------------------------------------------------- #
def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
    out, prev = b"", b""
    while len(out) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def encrypt_cryptojs(plaintext: bytes, passphrase: str = PASSPHRASE) -> str:
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(b"Salted__" + salt + ct).decode()


def decrypt_cryptojs(b64_blob: str, passphrase: str = PASSPHRASE) -> bytes:
    raw = base64.b64decode(b64_blob)
    if raw[:8] != b"Salted__":
        raise ValueError("not a CryptoJS Salted__ blob")
    salt, ct = raw[8:16], raw[16:]
    key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def jwt_seconds_left(token: str) -> int:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
        return int(exp - time.time())
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #
def load_sessions() -> dict:
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_sessions(sessions: dict) -> None:
    tmp = SESSION_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(sessions, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SESSION_FILE)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def api_call(session: requests.Session, method: str, path: str,
             *, params=None, body=None, token=None, auth=False) -> dict:
    headers = {}
    if auth:
        headers.update(AUTH_HEADERS)
        if token:
            headers["token"] = token

    r = session.request(method, API_BASE + path, params=params, data=body,
                        headers=headers, timeout=30)
    try:
        payload = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    if payload.get("code") not in (200, 201, 202) or payload.get("status") not in ("SUCCESS", None):
        err = RuntimeError(payload.get("message") or f"HTTP {r.status_code}")
        err.payload = payload  # type: ignore[attr-defined]
        raise err
    return payload


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #
def do_login(mobile: str) -> Optional[dict]:
    sess = requests.Session()
    sess.headers.update(HEADERS)

    print(f"[*] Sending OTP to {mobile} ...")
    try:
        enc = encrypt_cryptojs(
            json.dumps({"mobile": mobile}, separators=(",", ":")).encode()
        )
        resp = api_call(
            sess, "POST",
            "/gyftrapi/api/v1/chrismas/checkMobile",
            params={"campaign": CAMPAIGN},
            body=json.dumps({"encryptedBody": enc}, separators=(",", ":")),
        )
        print(f"    {resp.get('message')}")
    except Exception as exc:
        print(f"[!] Could not send OTP: {exc}")
        return None

    otp = input("Enter OTP: ").strip()
    if not otp:
        print("[!] No OTP entered.")
        return None

    print("[*] Verifying OTP ...")
    try:
        enc = encrypt_cryptojs(
            json.dumps({"mobile": mobile, "otp": otp}, separators=(",", ":")).encode()
        )
        resp = api_call(
            sess, "POST",
            "/gyftrapi/api/v1/chrismas/validateOtp",
            params={"campaign": CAMPAIGN},
            body=json.dumps({"encryptedBody": enc}, separators=(",", ":")),
        )
    except Exception as exc:
        print(f"[!] OTP verification failed: {exc}")
        return None

    token = resp.get("token")
    if not token:
        print("[!] Server did not return a token.")
        return None
    print("    OTP verified.")

    print("[*] Fetching profile ...")
    try:
        resp = api_call(
            sess, "GET", "/gyftrapi/api/v1/user/profile",
            params={"_": str(int(time.time() * 1000))},
            token=token, auth=True,
        )
        if resp.get("token"):
            token = resp["token"]
    except Exception as exc:
        print(f"[!] Profile call failed ({exc}); keeping validateOtp token.")

    return {
        "mobile": mobile,
        "token": token,
        "campaign": CAMPAIGN,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "expires_in_s": jwt_seconds_left(token),
    }


# --------------------------------------------------------------------------- #
# Profile
# --------------------------------------------------------------------------- #
def fetch_profile(token: str) -> Optional[dict]:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    try:
        resp = api_call(
            sess, "GET", "/gyftrapi/api/v1/user/profile",
            params={"_": str(int(time.time() * 1000))},
            token=token, auth=True,
        )
    except Exception as exc:
        print(f"[!] Profile fetch failed: {exc}")
        return None

    decrypted = None
    if resp.get("data") and isinstance(resp["data"], str):
        try:
            raw = decrypt_cryptojs(resp["data"]).decode()
            try:
                decrypted = json.loads(raw)
            except json.JSONDecodeError:
                decrypted = raw
        except Exception:
            pass

    return {
        "raw": resp,
        "decrypted": decrypted,
        "rotated_token": resp.get("token"),
    }


# --------------------------------------------------------------------------- #
# Points prompt
# --------------------------------------------------------------------------- #
def ask_points() -> Optional[int]:
    """
    Ask the user for a points value between MIN_POINTS and MAX_POINTS (inclusive).
    Returns None if the user cancels (empty input or Ctrl+C handled by caller).
    Re-prompts on invalid input instead of giving up.
    """
    while True:
        raw = input(
            f"Enter points to play ({MIN_POINTS}-{MAX_POINTS}), blank to cancel: "
        ).strip()
        if not raw:
            return None
        try:
            pts = int(raw)
        except ValueError:
            print(f"[!] Not a number: {raw!r} — try again.")
            continue
        if pts < MIN_POINTS or pts > MAX_POINTS:
            print(f"[!] Out of range — must be {MIN_POINTS}..{MAX_POINTS}, got {pts}.")
            continue
        return pts


# --------------------------------------------------------------------------- #
# Gameplay
# --------------------------------------------------------------------------- #
def play_game(token: str, user_type: str, points: int) -> Optional[dict]:
    """
    POST /gyftrapi/api/v1/caimpaign/diwali2026
    Body: AES({"user_type":"<type>","points":<int>})
    Response `data` is plain JSON: {"epay": <amount>, "luckuser": <bool>}
    """
    sess = requests.Session()
    sess.headers.update(HEADERS)

    payload = {"user_type": user_type, "points": points}
    print(f"[*] Playing {CAMPAIGN}  user_type={user_type}  points={points} ...")
    enc = encrypt_cryptojs(json.dumps(payload, separators=(",", ":")).encode())
    try:
        resp = api_call(
            sess, "POST", PLAY_PATH,
            body=json.dumps({"encryptedBody": enc}, separators=(",", ":")),
            token=token, auth=True,
        )
    except Exception as exc:
        raw = getattr(exc, "payload", None)
        print(f"[!] Play failed: {exc}")
        if raw:
            print("    Raw response:")
            print("    " + json.dumps(raw, indent=2).replace("\n", "\n    "))
        return None

    return {
        "message": resp.get("message"),
        "data": resp.get("data") or {},
        "raw": resp,
        "points_sent": points,
    }


def show_play_result(result: dict) -> None:
    data = result.get("data") or {}
    epay = data.get("epay")
    lucky = bool(data.get("luckuser"))

    print()
    print("============================================================")
    print("  PLAY RESULT")
    print("============================================================")
    print(f"  Message   : {result.get('message') or '(none)'}")
    print(f"  Points    : {result.get('points_sent')}")
    if epay is not None:
        print(f"  E-pay     : ₹{epay}")
    print(f"  Lucky     : {'★ YES' if lucky else 'no'}")
    extra = {k: v for k, v in data.items() if k not in ("epay", "luckuser")}
    if extra:
        print("  Extra     :")
        print("  " + json.dumps(extra, indent=2).replace("\n", "\n  "))
    print("============================================================")
    print()


# --------------------------------------------------------------------------- #
# Menu / session reuse
# --------------------------------------------------------------------------- #
def show_menu(sessions: dict) -> tuple[str, Optional[str]]:
    if not sessions:
        print("No saved sessions found — please log in.\n")
        return "login", None

    print("\n=== Gyftr Login ===")
    print("1) Login with a new number")
    print("2) Choose a saved session")

    choice = input("Choose [1/2]: ").strip() or "1"
    if choice == "2":
        print("\nSaved sessions:")
        items = list(sessions.items())
        for i, (mobile, s) in enumerate(items, 1):
            left = jwt_seconds_left(s.get("token", ""))
            status = f"valid ~{left // 86400}d" if left > 0 else "EXPIRED"
            print(f"  {i}) {mobile}   [{status}]   saved {s.get('saved_at', '?')}")

        pick = input("Pick a # (blank to cancel): ").strip()
        if not pick:
            return "cancel", None
        try:
            idx = int(pick) - 1
            return "session", items[idx][0]
        except (ValueError, IndexError):
            print("[!] Invalid choice.")
            return "cancel", None

    return "login", None


def use_saved_session(sessions: dict, mobile: str) -> bool:
    entry = sessions.get(mobile)
    if not entry or not entry.get("token"):
        print(f"[!] No token stored for {mobile}.")
        return False
    if jwt_seconds_left(entry["token"]) <= 0:
        print(f"[!] Session for {mobile} has expired — please log in again.")
        return False

    print(f"[*] Checking saved session for {mobile} ...")
    profile = fetch_profile(entry["token"])
    if profile is None:
        return False

    if profile.get("rotated_token"):
        entry["token"] = profile["rotated_token"]
        entry["expires_in_s"] = jwt_seconds_left(entry["token"])
        save_sessions(sessions)
    return True


def print_profile(profile: Optional[dict]) -> None:
    if not profile:
        return
    decrypted = profile.get("decrypted")
    if not decrypted:
        return
    print("\n=== PLAYER PROFILE ===")
    if isinstance(decrypted, (dict, list)):
        print(json.dumps(decrypted, indent=2))
    else:
        print(decrypted)
    print()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    sessions = load_sessions()

    mode, mobile = show_menu(sessions)
    if mode == "cancel":
        print("Bye.")
        return 0

    token: Optional[str] = None

    if mode == "login":
        mobile = input("Enter mobile number: ").strip()
        if not mobile:
            print("[!] No number entered.")
            return 1
        result = do_login(mobile)
        if result is None:
            print("\n[-] LOGIN FAILED\n")
            return 1
        sessions[mobile] = result
        save_sessions(sessions)
        token = result["token"]
        print(f"\n[+] LOGIN SUCCESS")
        print(f"    Session saved in {SESSION_FILE} for {mobile}")

    elif mode == "session" and mobile:
        if not use_saved_session(sessions, mobile):
            print("\n[-] LOGIN FAILED (session unusable)\n")
            return 1
        token = sessions[mobile]["token"]
        print(f"\n[+] LOGIN SUCCESS (saved session for {mobile})")

    if not token:
        print("[!] No token available.")
        return 1

    # Profile: gives user_type, alreadyPlayed, epay_balance, rotated token
    profile = fetch_profile(token)
    if profile and profile.get("rotated_token"):
        sessions[mobile]["token"] = profile["rotated_token"]
        sessions[mobile]["expires_in_s"] = jwt_seconds_left(profile["rotated_token"])
        token = profile["rotated_token"]
        save_sessions(sessions)
    print_profile(profile)

    pdata = profile.get("decrypted") if profile else None
    user_type = "B2C"
    already_played = False
    if isinstance(pdata, dict):
        user_type = str(pdata.get("user_type") or "B2C")
        already_played = bool(pdata.get("alreadyPlayed"))
        if pdata.get("epay_balance") is not None:
            print(f"[i] Current e-pay balance: ₹{pdata.get('epay_balance')}")

    if already_played:
        print(f"[!] This account has already played {CAMPAIGN} today.")
        return 0

    # Ask user how many points to play
    pts = ask_points()
    if pts is None:
        print("Cancelled — no play.")
        return 0

    play = play_game(token, user_type=user_type, points=pts)
    if play is None:
        print("[-] PLAY FAILED")
        return 2

    show_play_result(play)

    # Refresh so epay_balance reflects the credit, and rotate token
    post = fetch_profile(token)
    if post and post.get("rotated_token"):
        sessions[mobile]["token"] = post["rotated_token"]
        sessions[mobile]["expires_in_s"] = jwt_seconds_left(post["rotated_token"])
        save_sessions(sessions)
    if post and isinstance(post.get("decrypted"), dict):
        new_balance = post["decrypted"].get("epay_balance")
        if new_balance is not None:
            print(f"[i] Updated e-pay balance: ₹{new_balance}")

    print("[+] DONE")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)