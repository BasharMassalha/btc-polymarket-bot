import websocket, requests, json, time, sqlite3, threading, os
from collections import deque
from datetime import datetime, timezone
from dotenv import load_dotenv
import numpy as np
import sys

# Ensure Unicode output works in Windows terminals.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.join(SCRIPT_DIR, ".env")
# override=True: Windows/user env vars (even empty) would otherwise block .env values
load_dotenv(dotenv_path=_ENV_PATH, override=True)


def _load_env_manual_fallback(path):
    """If dotenv missed keys (BOM/encoding), set missing vars from simple KEY=VALUE lines."""
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and v and os.getenv(k) in (None, ""):
                    os.environ[k] = v
    except OSError:
        pass


_load_env_manual_fallback(_ENV_PATH)


def first_env(*keys, default=""):
    for k in keys:
        v = os.getenv(k)
        if v is not None and str(v).strip() != "":
            return str(v).strip().strip('"').strip("'")
    return default

def normalize_private_key(raw_key):
    if not raw_key:
        return ""
    key = str(raw_key).strip().strip('"').strip("'")
    if key.startswith("0x"):
        key = key[2:]
    # 32-byte EVM private key should be 64 hex chars.
    if len(key) != 64:
        return key
    try:
        int(key, 16)
        return "0x" + key
    except ValueError:
        return key


def poly_private_key():
    """Always read from env (avoids stale empty module-level values)."""
    return normalize_private_key(
        first_env("POLY_PRIVATE_KEY", "PRIVATE_KEY", "POLYMARKET_PRIVATE_KEY")
    )


def poly_funder():
    return first_env(
        "POLY_FUNDER", "FUNDER", "POLYMARKET_FUNDER", "POLY_PROXY_WALLET"
    )


def poly_sig_type_int():
    try:
        return int(float(first_env("POLY_SIG_TYPE", "POLY_SIGNATURE_TYPE", default="1")))
    except (ValueError, TypeError):
        return 1


def poly_sig_types_to_try():
    """
    Signature modes for CLOB (Polymarket py-clob-client / OrderBuilder):
      0 = EOA (MetaMask-style key controls funds directly)
      1 = POLY_PROXY (email / Magic-exported key + profile proxy funder)
      2 = GNOSIS_SAFE (browser wallet proxy — MetaMask/Rabby/Privy; same pattern)

    Try .env POLY_SIG_TYPE first, then other modes. Wrong type often yields
    'invalid signature' or balance/allowance errors even when UI shows USDC.
    """
    st = max(0, min(2, int(poly_sig_type_int())))
    ordered = []
    for x in (st, 2, 1, 0):
        if x not in ordered:
            ordered.append(x)
    return ordered


def _format_poly_err(err):
    """Full API error text for debugging (PolyApiException has error_message dict)."""
    try:
        from py_clob_client.exceptions import PolyApiException

        if isinstance(err, PolyApiException):
            em = getattr(err, "error_message", None)
            if em is not None:
                return repr(em) if not isinstance(em, str) else em
    except Exception:
        pass
    return str(err)


def _should_refresh_allowance(post_err_text: str) -> bool:
    m = post_err_text.lower()
    if "liquidity" in m and "not enough" in m:
        return False
    if "not enough balance / allowance" in m:
        return True
    if "not enough allowance" in m:
        return True
    if "allowance" in m and ("not enough" in m or "insufficient" in m):
        return True
    if "not enough" in m and "balance" in m and "liquidity" not in m:
        return True
    return False


_poly_clob_http_patched = False


def _ensure_polymarket_httpx_client():
    """
    py_clob_client uses a global httpx client with http2=True and default timeouts.
    On some Windows / ISP setups that causes PolyApiException[Request exception!]
    (no HTTP status). Use HTTP/1.1 + longer timeouts once per process.
    """
    global _poly_clob_http_patched
    if _poly_clob_http_patched:
        return
    try:
        import httpx
        import py_clob_client.http_helpers.helpers as poly_http

        old = getattr(poly_http, "_http_client", None)
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        poly_http._http_client = httpx.Client(
            http2=False,
            timeout=httpx.Timeout(60.0, connect=25.0, read=60.0, write=60.0),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=20),
        )
        _poly_clob_http_patched = True
    except Exception as e:
        print(f"  [Poly HTTP] Could not tune httpx client: {e}")


def _is_transient_poly_network_error(err) -> bool:
    """True when no HTTP response (connection drop, timeout, TLS, etc.)."""
    try:
        from py_clob_client.exceptions import PolyApiException

        if isinstance(err, PolyApiException) and getattr(err, "status_code", 0) is None:
            return True
    except Exception:
        pass
    t = str(err).lower()
    if "request exception" in t:
        return True
    if "timeout" in t or "timed out" in t:
        return True
    if "connection" in t and ("reset" in t or "refused" in t or "aborted" in t):
        return True
    return False


def _retry_polymarket_call(label, fn, attempts=5, *, fast=False):
    """
    Retry transient network failures with backoff.
    Use fast=True for post_order paths so signatures are not left to expire on the server.
    """
    delay = 0.75 if fast else 1.5
    cap = 6.0 if fast else 20.0
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last = e
            if not _is_transient_poly_network_error(e) or i >= attempts - 1:
                raise
            print(
                f"  [Bet] {label} network issue ({_format_poly_err(e)}), "
                f"retry {i + 2}/{attempts} in {delay:.1f}s…"
            )
            time.sleep(delay)
            delay = min(delay * 1.8, cap)
    raise last


def _is_order_too_old_error(err_text: str) -> bool:
    return "order too old" in str(err_text).lower()


# ════════════════════════════════════════════════
#   SETTINGS
# ════════════════════════════════════════════════
BET_AMOUNT       = 5.0
MIN_CONFIDENCE   = 76
MIN_SIGNALS      = 3
# DRY_RUN: set in .env as true/false/1/0, or override below
_dry_raw = first_env("DRY_RUN", default="")
if _dry_raw:
    DRY_RUN = str(_dry_raw).strip().lower() in ("1", "true", "yes", "y", "on")
else:
    DRY_RUN = False  # change to True here to force dry-run without .env

POLY_API_KEY = first_env("POLY_API_KEY", "CLOB_API_KEY")

if not poly_private_key():
    print(
        "  [Env] POLY_PRIVATE_KEY still empty.\n"
        "        Tip: check your .env file exists next to the script and contains POLY_PRIVATE_KEY.\n"
        "        Also remove POLY_PRIVATE_KEY from Windows Environment Variables if set."
    )
# ════════════════════════════════════════════════

price_history  = deque(maxlen=120)
volume_history = deque(maxlen=60)
prob_history   = deque(maxlen=60)
pair_history   = deque(maxlen=60)
current_price  = [0.0]
current_volume = [0.0]
lock = threading.Lock()

# ── Window-start price tracking ──
# The market resolves: "end price >= start price → UP, else DOWN".
# Knowing the start price lets us observe which side is already winning.
bucket_start_price = [0.0]
bucket_start_ts    = [0]

EDGE_MARGIN          = 0.08   # only bet when estimated P(win) > implied + this
MIN_DISPLACEMENT_PCT = 0.03   # BTC must have moved >= 0.03% from window start
SAFE_WINDOW_MIN      = 60     # don't bet with < 60s left (execution risk)
SAFE_WINDOW_MAX      = 150    # don't bet with > 150s left (too much reversal risk)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "predictions.db")
db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA synchronous=NORMAL")
db.execute("PRAGMA busy_timeout=30000")

db.executescript("""
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY,
    ts REAL, direction TEXT, confidence REAL,
    regime TEXT, price REAL, signals INTEGER,
    outcome TEXT DEFAULT 'PENDING', resolved INTEGER DEFAULT 0,
    sig_ob INTEGER, sig_vpin INTEGER, sig_rsi INTEGER,
    sig_mom INTEGER, sig_ema INTEGER, sig_fund INTEGER,
    sig_poly INTEGER, sig_squeeze INTEGER
);

CREATE TABLE IF NOT EXISTS signal_stats (
    signal_name TEXT PRIMARY KEY,
    correct INTEGER DEFAULT 0,
    total   INTEGER DEFAULT 0,
    weight  REAL    DEFAULT 1.0,
    streak  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS calibration (
    id INTEGER PRIMARY KEY CHECK (id=1),
    conf_threshold REAL DEFAULT 74.0
);

INSERT OR IGNORE INTO calibration (id, conf_threshold) VALUES (1, 74.0);
""")

SIGNAL_WEIGHTS_DEFAULT = {
    'displacement': 3.5,
    'order_book'  : 2.0,
    'vpin'        : 1.8,
    'funding_rate': 1.5,
    'polymarket'  : 1.4,
    'momentum'    : 1.2,
    'ema'         : 1.0,
    'rsi'         : 0.9,
    'squeeze'     : 0.8,
}

WEIGHT_MIN  = 0.2
WEIGHT_MAX  = 3.5
WEIGHT_STEP = 0.12
STREAK_SUPPRESS = 4

db.executemany(
    "INSERT OR IGNORE INTO signal_stats (signal_name, weight) VALUES (?,?)",
    [(k, v) for k, v in SIGNAL_WEIGHTS_DEFAULT.items()],
)
db.commit()

# Ensure vote columns exist (for older DBs).
required_prediction_cols = [
    "sig_ob", "sig_vpin", "sig_rsi", "sig_mom",
    "sig_ema", "sig_fund", "sig_poly", "sig_squeeze",
    "market_slug", "poly_prob", "bucket_price",
]
existing_prediction_cols = {r[1] for r in db.execute("PRAGMA table_info(predictions)").fetchall()}
_col_type_map = {"market_slug": "TEXT", "poly_prob": "REAL", "bucket_price": "REAL"}
for c in required_prediction_cols:
    if c not in existing_prediction_cols:
        ctype = _col_type_map.get(c, "INTEGER")
        db.execute(f"ALTER TABLE predictions ADD COLUMN {c} {ctype}")
db.commit()

# ════════════════════════════════════════════════
#   POLYMARKET
# ════════════════════════════════════════════════
def get_current_slug():
    now    = int(time.time())
    bucket = (now // 300) * 300
    return f"btc-updown-5m-{bucket}"

def get_next_slug():
    now    = int(time.time())
    bucket = (now // 300) * 300 + 300
    return f"btc-updown-5m-{bucket}"

def get_market_seconds_left():
    now    = int(time.time())
    bucket = (now // 300) * 300
    return 300 - (now - bucket)

def parse_iso_ts(ts):
    if not ts:
        return None
    try:
        # Gamma timestamps are typically ISO-8601 with trailing Z.
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None

def score_market_candidate(market):
    """
    Higher score = better candidate for current BTC 5m up/down market.
    """
    q = str(market.get('question', '')).lower()
    slug = str(market.get('slug', '')).lower()
    score = 0

    if 'btc' in q or 'bitcoin' in q or 'btc' in slug or 'bitcoin' in slug:
        score += 6
    if '5' in q or '5m' in q or '5-minute' in q or '5 min' in q:
        score += 5
    if any(x in q for x in ('up', 'down', 'higher', 'lower')) or \
       any(x in slug for x in ('up', 'down', 'higher', 'lower')):
        score += 4
    if market.get('active', True):
        score += 1

    # Prefer markets ending near the next few minutes.
    end_dt = parse_iso_ts(market.get('endDate') or market.get('end_date'))
    if end_dt:
        now_dt = datetime.now(timezone.utc)
        secs_to_end = (end_dt - now_dt).total_seconds()
        if 20 <= secs_to_end <= 420:
            score += 6
        elif 0 <= secs_to_end <= 900:
            score += 3
        elif secs_to_end < 0:
            score -= 3

    return score

def find_btc_market():
    for slug in [get_current_slug(), get_next_slug()]:
        try:
            r = requests.get(
                "https://gamma-api.polymarket.com/markets",
                params={"slug": slug},
                timeout=8
            )
            if r.status_code == 200:
                data    = r.json()
                markets = data if isinstance(data, list) \
                          else data.get('markets', [])
                if markets:
                    return markets[0]
        except:
            pass

    # Fallback #1: broad active BTC market scan + scoring.
    try:
        r = requests.get(
            "https://gamma-api.polymarket.com/markets",
            params={"active": "true", "tag_slug": "bitcoin", "limit": 100},
            timeout=8
        )
        if r.status_code == 200:
            data    = r.json()
            markets = data if isinstance(data, list) \
                      else data.get('markets', [])

            ranked = sorted(markets, key=score_market_candidate, reverse=True)
            if ranked and score_market_candidate(ranked[0]) >= 8:
                return ranked[0]
    except:
        pass

    return None

def get_yes_probability(market):
    if not market:
        return 0.5
    try:
        outcomes = market.get('outcomes', [])
        prices   = market.get('outcomePrices', [])
        if outcomes and prices:
            for i, o in enumerate(outcomes):
                if any(x in str(o).lower() for x in ['yes', 'up', 'higher']):
                    return float(prices[i])
        for t in market.get('tokens', []):
            if any(x in t.get('outcome', '').lower() for x in ['yes', 'up', 'higher']):
                return float(t['price'])
        if prices:
            return float(prices[0])
    except:
        pass
    return 0.5

UP_OUTCOME_KEYWORDS = ('yes', 'up', 'higher')
DOWN_OUTCOME_KEYWORDS = ('no', 'down', 'lower')

def normalize_token_ids(raw_token_ids):
    if isinstance(raw_token_ids, list):
        return raw_token_ids
    if isinstance(raw_token_ids, str):
        try:
            parsed = json.loads(raw_token_ids)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []

def get_token_id(market, direction):
    try:
        outcomes = market.get('outcomes', [])
        token_ids = normalize_token_ids(market.get('clobTokenIds', []))

        if outcomes and token_ids:
            for i, o in enumerate(outcomes):
                o_lower = str(o).lower()
                if direction == 'UP' and i < len(token_ids) and any(x in o_lower for x in UP_OUTCOME_KEYWORDS):
                    return token_ids[i]
                if direction == 'DOWN' and i < len(token_ids) and any(x in o_lower for x in DOWN_OUTCOME_KEYWORDS):
                    return token_ids[i]

            # Fallback by position if labels are not matched.
            if direction == 'UP' and len(token_ids) > 0:
                return token_ids[0]
            if direction == 'DOWN' and len(token_ids) > 1:
                return token_ids[1]

        for t in market.get('tokens', []):
            o = t.get('outcome', '').lower()
            if direction == 'UP' and any(x in o for x in UP_OUTCOME_KEYWORDS):
                return t.get('token_id')
            if direction == 'DOWN' and any(x in o for x in DOWN_OUTCOME_KEYWORDS):
                return t.get('token_id')

        # Last resort by position.
        tokens = market.get('tokens', [])
        if direction == 'UP' and len(tokens) > 0:
            return tokens[0].get('token_id')
        if direction == 'DOWN' and len(tokens) > 1:
            return tokens[1].get('token_id')
    except Exception as e:
        print(f"  [Token ID] Error: {e}")
    return None

def place_bet(market, direction, amount, *, force_live=False):
    """
    Place a market buy. If DRY_RUN is True, only prints unless force_live=True
    (used by --test-bet to confirm real trading still works).
    """
    if DRY_RUN and not force_live:
        print(f"  [DRY RUN] Would bet ${amount:.2f} on {direction}")
        return True
    pk = poly_private_key()
    fd = poly_funder()
    if not pk:
        print("  [Bet] POLY_PRIVATE_KEY missing from .env")
        return False
    if not fd:
        print("  [Bet] POLY_FUNDER missing from .env")
        return False
    try:
        from py_clob_client.client import ClobClient
        from py_clob_client.clob_types import AssetType, BalanceAllowanceParams, MarketOrderArgs, OrderType
        from py_clob_client.order_builder.constants import BUY

        _ensure_polymarket_httpx_client()

        token_id = get_token_id(market, direction)
        if not token_id:
            print("  [Bet] Could not find token ID")
            return False

        # Try signature types 0 / 1 / 2 — wrong type → invalid signature or bogus balance errors.
        last_err = None
        for sig_type in poly_sig_types_to_try():
            try:
                client = ClobClient(
                    "https://clob.polymarket.com",
                    key=pk,
                    chain_id=137,
                    signature_type=int(sig_type),
                    funder=fd,
                )
                client.set_api_creds(
                    _retry_polymarket_call(
                        "Get API creds",
                        lambda: client.create_or_derive_api_creds(),
                    )
                )
                signed = _retry_polymarket_call(
                    "Build market order",
                    lambda: client.create_market_order(
                        MarketOrderArgs(
                            token_id=token_id,
                            amount=amount,
                            side=BUY,
                            order_type=OrderType.FOK,
                        )
                    ),
                    fast=True,
                )
                try:
                    # fast retries: long waits can expire signed orders server-side ("order too old")
                    resp = _retry_polymarket_call(
                        "Submit order",
                        lambda: client.post_order(signed, OrderType.FOK),
                        attempts=3,
                        fast=True,
                    )
                except Exception as post_err:
                    full = _format_poly_err(post_err)
                    print(f"  [Bet] Order rejected: {full}")
                    post_msg = full.lower()
                    if _should_refresh_allowance(full):
                        print(
                            "  [Bet] Attempting collateral allowance refresh "
                            f"(sig_type={sig_type})…"
                        )
                        params = BalanceAllowanceParams(
                            asset_type=AssetType.COLLATERAL,
                            signature_type=int(sig_type),
                        )
                        _retry_polymarket_call(
                            "Refresh allowance",
                            lambda: client.update_balance_allowance(params),
                            attempts=3,
                            fast=True,
                        )
                        time.sleep(1.2)
                        signed = _retry_polymarket_call(
                            "Rebuild order",
                            lambda: client.create_market_order(
                                MarketOrderArgs(
                                    token_id=token_id,
                                    amount=amount,
                                    side=BUY,
                                    order_type=OrderType.FOK,
                                )
                            ),
                            fast=True,
                        )
                        resp = _retry_polymarket_call(
                            "Submit order (after allowance)",
                            lambda: client.post_order(signed, OrderType.FOK),
                            attempts=3,
                            fast=True,
                        )
                    elif _is_order_too_old_error(full):
                        print(
                            "  [Bet] 'Order too old' — signing a new order and posting immediately…"
                        )
                        print(
                            "  [Bet] Tip: sync Windows clock (Settings → Time & language → Sync now)."
                        )
                        signed = _retry_polymarket_call(
                            "Rebuild order (stale timestamp)",
                            lambda: client.create_market_order(
                                MarketOrderArgs(
                                    token_id=token_id,
                                    amount=amount,
                                    side=BUY,
                                    order_type=OrderType.FOK,
                                )
                            ),
                            attempts=3,
                            fast=True,
                        )
                        resp = _retry_polymarket_call(
                            "Submit order (fresh sign)",
                            lambda: client.post_order(signed, OrderType.FOK),
                            attempts=3,
                            fast=True,
                        )
                    else:
                        raise
                print(f"  [Bet] ✅ Order placed (sig_type={sig_type}) → {resp}")
                return True
            except Exception as inner_e:
                last_err = inner_e
                msg = str(inner_e).lower()
                if "invalid signature" in msg:
                    print(
                        f"  [Bet] Signature rejected for sig_type={sig_type}, "
                        f"trying next mode… ({_format_poly_err(inner_e)})"
                    )
                    continue
                raise
        print(
            "  [Bet] Could not place order with any signature type (tried 0=EOA, 1=Poly proxy, 2=Gnosis)."
        )
        if last_err:
            print(f"  [Bet] Last error: {_format_poly_err(last_err)}")
        print(
            "  [Bet] Tips: POLY_FUNDER must be your Polymarket *profile/proxy* address "
            "(open your profile on polymarket.com — URL or UI), NOT the USDC deposit address. "
            "Try POLY_SIG_TYPE=2 if you use MetaMask/Rabby; POLY_SIG_TYPE=1 for email/Magic export."
        )
        return False
    except Exception as e:
        print(f"  [Bet] Error: {_format_poly_err(e)}")
        return False

def check_polymarket_account_access():
    """
    Fast startup auth probe so terminal shows account accessibility immediately.
    """
    if DRY_RUN:
        print("  [Access] DRY_RUN enabled, skipping live account probe")
        return True
    pk = poly_private_key()
    fd = poly_funder()
    if not pk or not fd:
        print("  [Access] Missing key/funder, cannot verify account access")
        return False

    try:
        from py_clob_client.client import ClobClient
        from py_clob_client.clob_types import AssetType, BalanceAllowanceParams
    except Exception as e:
        print(f"  [Access] py_clob_client import failed: {e}")
        return False

    _ensure_polymarket_httpx_client()

    for sig_type in poly_sig_types_to_try():
        try:
            client = ClobClient(
                "https://clob.polymarket.com",
                key=pk,
                chain_id=137,
                signature_type=int(sig_type),
                funder=fd,
            )
            creds = _retry_polymarket_call(
                "Get API creds",
                lambda: client.create_or_derive_api_creds(),
            )
            client.set_api_creds(creds)
            print(f"  [Access] ✅ Polymarket auth OK (sig_type={sig_type})")
            try:
                ba = _retry_polymarket_call(
                    "Read balance/allowance",
                    lambda: client.get_balance_allowance(
                        BalanceAllowanceParams(
                            asset_type=AssetType.COLLATERAL,
                            signature_type=int(sig_type),
                        )
                    ),
                )
                bal = alw = None
                if isinstance(ba, dict):
                    bal = ba.get("balance")
                    alw = ba.get("allowance")
                    # Some responses use alternate keys
                    if alw is None:
                        alw = ba.get("allowance_raw") or ba.get("collateral_allowance")
                # CLOB often returns balance as raw 6-decimal USDC integer
                bal_note = ""
                try:
                    if bal is not None and str(bal).isdigit() and int(bal) > 1000:
                        bal_note = f" (~{int(bal) / 1e6:.2f} USDC)"
                except (ValueError, TypeError):
                    pass
                alw_note = ""
                if alw is None:
                    alw_note = (
                        " (field omitted by API — not always zero; "
                        "if orders fail, bot will try to refresh allowance)"
                    )
                print(
                    f"  [Access] Collateral balance={bal}{bal_note}  "
                    f"allowance={alw}{alw_note}"
                )
            except Exception as e2:
                print(f"  [Access] Could not read balance/allowance: {e2}")
            return True
        except Exception as e:
            print(f"  [Access] sig_type={sig_type} failed: {_format_poly_err(e)}")
            if "invalid signature" in str(e).lower():
                continue
            break

    print("  [Access] ❌ Could not authenticate CLOB account (check key/funder/signature type)")
    return False

# ════════════════════════════════════════════════
#   SIGNALS
# ════════════════════════════════════════════════
def get_order_book_signal():
    try:
        r = requests.get(
            "https://api.binance.com/api/v3/depth",
            params={"symbol": "BTCUSDT", "limit": 10},
            timeout=5
        )
        data = r.json()
        weights = [1.0, 0.5, 0.25, 0.125, 0.0625]
        bid_w   = sum(float(data['bids'][i][1]) * weights[i] for i in range(min(5, len(data['bids']))))
        ask_w   = sum(float(data['asks'][i][1]) * weights[i] for i in range(min(5, len(data['asks']))))
        total   = bid_w + ask_w
        if total == 0:
            return 0, 0.5
        ratio   = bid_w / total
        if ratio > 0.62:
            return  1, ratio
        if ratio < 0.38:
            return -1, ratio
        if ratio > 0.56:
            return  1, ratio
        if ratio < 0.44:
            return -1, ratio
        return 0, ratio
    except:
        return 0, 0.5

def get_vpin_signal():
    try:
        r = requests.get(
            "https://api.binance.com/api/v3/trades",
            params={"symbol": "BTCUSDT", "limit": 150},
            timeout=5
        )
        trades = r.json()
        buy_vol  = sum(float(t['qty']) for t in trades if not t['isBuyerMaker'])
        sell_vol = sum(float(t['qty']) for t in trades if t['isBuyerMaker'])
        total    = buy_vol + sell_vol
        if total == 0:
            return 0, 0.5
        buy_ratio = buy_vol / total
        with lock:
            avg_vol = np.mean(list(volume_history)[-10:]) if len(volume_history) >= 5 else 0
        vol_spike = (total / avg_vol) if avg_vol > 0 else 1.0
        if buy_ratio > 0.63 and vol_spike > 1.4:
            return  1, buy_ratio
        if buy_ratio < 0.37 and vol_spike > 1.4:
            return -1, buy_ratio
        if buy_ratio > 0.58:
            return  1, buy_ratio
        if buy_ratio < 0.42:
            return -1, buy_ratio
        return 0, buy_ratio
    except:
        return 0, 0.5

def calc_rsi(period=14):
    with lock:
        if len(price_history) < period + 1:
            return 50.0
        prices = list(price_history)[-(period + 1):]
    gains  = [max(0, prices[i]-prices[i-1]) for i in range(1, len(prices))]
    losses = [max(0, prices[i-1]-prices[i]) for i in range(1, len(prices))]
    ag = np.mean(gains)  if gains  else 0
    al = np.mean(losses) if losses else 0
    if al == 0:
        return 100.0
    return 100.0 - (100.0 / (1 + ag/al))

def get_rsi_signal():
    rsi = calc_rsi()
    if rsi < 25: return  1, rsi
    if rsi > 75: return -1, rsi
    if rsi < 32: return  1, rsi
    if rsi > 68: return -1, rsi
    return 0, rsi

def get_momentum_signal():
    with lock:
        if len(price_history) < 10:
            return 0, 0.0
        p = list(price_history)
    short = (p[-1]-p[-3]) / p[-3]  * 100
    med   = (p[-1]-p[-6]) / p[-6]  * 100
    long_ = (p[-1]-p[-10])/ p[-10] * 100
    if short > 0.12  and med > 0.20  and long_ > 0.30:
        return  1, short
    if short < -0.12 and med < -0.20 and long_ < -0.30:
        return -1, short
    if short > 0.18  and med > 0.25:
        return  1, short
    if short < -0.18 and med < -0.25:
        return -1, short
    if short > 0.25:
        return  1, short
    if short < -0.25:
        return -1, short
    return 0, short

def calc_ema(prices, period):
    if len(prices) < period:
        return prices[-1] if prices else 0
    k   = 2 / (period + 1)
    ema = prices[0]
    for p in prices[1:]:
        ema = p * k + ema * (1 - k)
    return ema

def get_ema_signal():
    with lock:
        if len(price_history) < 26:
            return 0, 0.0
        p = list(price_history)
    ema9  = calc_ema(p, 9)
    ema21 = calc_ema(p, 21)
    diff  = (ema9 - ema21) / ema21 * 100
    if diff > 0.08:  return  1, diff
    if diff < -0.08: return -1, diff
    if diff > 0.03:  return  1, diff
    if diff < -0.03: return -1, diff
    return 0, diff

def get_funding_signal():
    try:
        r = requests.get(
            "https://fapi.binance.com/fapi/v1/premiumIndex",
            params={"symbol": "BTCUSDT"},
            timeout=5
        )
        data = r.json()
        funding = float(data.get('lastFundingRate', 0))
        mark    = float(data.get('markPrice', 0))
        index   = float(data.get('indexPrice', 0))
        premium = ((mark - index) / index * 100) if index > 0 else 0
        if funding > 0.0004 or premium > 0.05:
            return -1, funding
        if funding < -0.0004 or premium < -0.05:
            return  1, funding
        if funding > 0.0002:
            return -1, funding
        if funding < -0.0002:
            return  1, funding
        return 0, funding
    except:
        return 0, 0.0

def get_poly_signal(prob):
    with lock:
        if len(price_history) < 6 or len(prob_history) < 5:
            return 0, 0.0
        prices = list(price_history)
        probs  = list(prob_history)
    price_move = (prices[-1]-prices[-5]) / prices[-5] * 100
    prob_move  = probs[-1]-probs[-5]
    if price_move > 0.25 and prob_move < 0.04 and prob < 0.66:
        return  1, price_move
    if price_move < -0.25 and prob_move > -0.04 and prob > 0.36:
        return -1, price_move
    if prob_move > 0.09 and abs(price_move) < 0.10:
        return  1, prob_move * 100
    if prob_move < -0.09 and abs(price_move) < 0.10:
        return -1, prob_move * 100
    if prob > 0.78:
        return  1, prob
    if prob < 0.22:
        return -1, prob
    return 0, 0.0

def get_squeeze_signal():
    with lock:
        if len(price_history) < 20:
            return 0, 0.0
        p = list(price_history)
    mean = np.mean(p[-20:])
    std  = np.std(p[-20:])
    bw   = (std / mean) * 100
    dir5 = p[-1] - p[-5]
    if bw < 0.15 and dir5 > 0: return  1, bw
    if bw < 0.15 and dir5 < 0: return -1, bw
    if bw < 0.25 and dir5 > 0: return  1, bw
    if bw < 0.25 and dir5 < 0: return -1, bw
    return 0, bw


def get_displacement_info():
    """BTC displacement from window start (%) and realized 5-min volatility."""
    bp = bucket_start_price[0]
    cp = current_price[0]
    if bp <= 0 or cp <= 0:
        return 0.0, 0.06
    displacement_pct = (cp - bp) / bp * 100
    with lock:
        if len(price_history) < 10:
            return displacement_pct, 0.06
        p = list(price_history)
    rets = [(p[i] - p[i - 1]) / p[i - 1] * 100 for i in range(1, len(p))]
    vol_1m = float(np.std(rets)) if len(rets) > 2 else 0.06
    vol_5m = vol_1m * (5 ** 0.5)
    return displacement_pct, max(vol_5m, 0.01)


def _norm_cdf(x):
    """Standard normal CDF (Abramowitz & Stegun 26.2.17)."""
    if x > 6:
        return 1.0
    if x < -6:
        return 0.0
    t = 1.0 / (1.0 + 0.2316419 * abs(x))
    d = 0.3989422804014327
    p = d * np.exp(-0.5 * x * x) * t * (
        0.319381530
        + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429)))
    )
    return 1.0 - p if x > 0 else p


def estimate_true_prob_up(displacement_pct, time_remaining_s, vol_5m):
    """
    Random-walk estimate: P(end >= start) given current displacement.
    As time_remaining shrinks and displacement grows, the probability converges to 0 or 1.
    """
    if vol_5m <= 0:
        return 0.5
    remaining_frac = max(time_remaining_s, 1) / 300.0
    remaining_vol = vol_5m * (remaining_frac ** 0.5)
    if remaining_vol < 1e-9:
        return 1.0 if displacement_pct > 0 else 0.0
    z = displacement_pct / remaining_vol
    return _norm_cdf(z)


def compute_edge(direction, poly_prob, displacement_pct, time_remaining_s, vol_5m):
    """
    Returns (estimated_win_prob, implied_prob, edge).
    edge > 0 means there is value; we only bet when edge >= EDGE_MARGIN.
    """
    p_up = estimate_true_prob_up(displacement_pct, time_remaining_s, vol_5m)
    if direction == "UP":
        estimated = p_up
        implied = poly_prob
    else:
        estimated = 1.0 - p_up
        implied = 1.0 - poly_prob
    edge = estimated - implied
    return round(estimated, 4), round(implied, 4), round(edge, 4)


def get_displacement_signal():
    """Primary signal: has BTC already moved meaningfully from window start?"""
    disp, _ = get_displacement_info()
    if abs(disp) < MIN_DISPLACEMENT_PCT:
        return 0, disp
    return (1 if disp > 0 else -1), disp


# ════════════════════════════════════════════════
#   ADAPTIVE WEIGHTS & CALIBRATION
# ════════════════════════════════════════════════
def get_live_weights():
    rows = db.execute("SELECT signal_name, weight FROM signal_stats").fetchall()
    weights = {name: w for name, w in rows} if rows else {}
    for name, w in SIGNAL_WEIGHTS_DEFAULT.items():
        weights.setdefault(name, w)
    for name, w in list(weights.items()):
        weights[name] = max(WEIGHT_MIN, min(WEIGHT_MAX, float(w)))
    return weights

def update_signal_weights(predicted_direction, signal_votes, outcome_correct):
    """
    Credit/penalize only signals that voted with our prediction direction.
    `streak` is consecutive losses (0 = not currently in a loss streak).
    """
    direction_val = 1 if predicted_direction == "UP" else -1
    weights = get_live_weights()

    for signal_name, vote in signal_votes.items():
        if vote != direction_val:
            continue

        row = db.execute(
            "SELECT correct, total, weight, streak FROM signal_stats WHERE signal_name=?",
            (signal_name,)
        ).fetchone()
        if row:
            correct, total, stored_weight, streak = row
        else:
            correct, total, stored_weight, streak = 0, 0, weights.get(signal_name, 1.0), 0

        new_total = total + 1
        if outcome_correct:
            new_correct = correct + 1
            new_streak = 0
            new_weight = float(stored_weight) + WEIGHT_STEP
        else:
            new_correct = correct
            new_streak = streak + 1
            new_weight = float(stored_weight) - WEIGHT_STEP

            # Losing streak suppressor: 4+ consecutive losses => halve weight.
            if new_streak >= STREAK_SUPPRESS:
                new_weight *= 0.5

        new_weight = round(max(WEIGHT_MIN, min(WEIGHT_MAX, new_weight)), 3)
        db.execute(
            "UPDATE signal_stats SET correct=?, total=?, weight=?, streak=? WHERE signal_name=?",
            (new_correct, new_total, new_weight, new_streak, signal_name)
        )

def auto_tune_threshold():
    row = db.execute("""
        SELECT COUNT(*), SUM(CASE WHEN outcome LIKE 'CORRECT%' THEN 1 ELSE 0 END)
        FROM (SELECT * FROM predictions WHERE resolved=1 ORDER BY id DESC LIMIT 20)
    """).fetchone()
    if not row or not row[0] or row[0] < 20:
        return

    wr = row[1] / row[0]
    cal = db.execute("SELECT conf_threshold FROM calibration WHERE id=1").fetchone()
    current = cal[0] if cal else 74.0

    if wr > 0.60:
        new = max(65.0, current - 1.5)
    elif wr < 0.45:
        new = min(84.0, current + 1.5)
    else:
        return

    db.execute("UPDATE calibration SET conf_threshold=? WHERE id=1", (round(new, 1),))
    db.commit()

def get_effective_threshold():
    row = db.execute("SELECT conf_threshold FROM calibration WHERE id=1").fetchone()
    return row[0] if row else MIN_CONFIDENCE

# ════════════════════════════════════════════════
#   MARKET REGIME DETECTION
# ════════════════════════════════════════════════
def detect_regime():
    with lock:
        if len(price_history) < 20:
            return 'ranging'
        p = list(price_history)

    mean = np.mean(p[-20:])
    std  = np.std(p[-20:])
    last20 = p[-20:]
    diffs = [abs(last20[i] - last20[i - 1]) for i in range(1, len(last20))]
    atr   = np.mean(diffs) / mean * 100 if mean != 0 else 0
    bandwidth = (std / mean) * 100 if mean != 0 else 0

    # Short slope over last 5 candles: compare p[-1] vs p[-6]
    short_base = p[-6]
    long_base  = p[-16]
    short_slope = ((p[-1] - short_base) / short_base * 100) if short_base != 0 else 0
    long_slope  = ((p[-1] - long_base) / long_base * 100) if long_base != 0 else 0

    if atr > 0.12 or bandwidth > 0.35:
        return 'volatile'
    if abs(short_slope) > 0.20 and abs(long_slope) > 0.25:
        return 'trend_up' if long_slope > 0 else 'trend_down'
    return 'ranging'

# ════════════════════════════════════════════════
#   NOISE FILTERS
# ════════════════════════════════════════════════
def is_price_stable():
    with lock:
        if len(price_history) < 3:
            return True
        p = list(price_history)
    # BTC moved more than 0.40% over last 2 candles => chase filter fails.
    return abs(p[-1]-p[-3]) / p[-3] * 100 <= 0.40

def is_volume_normal():
    with lock:
        if len(volume_history) < 10:
            return True
        v = list(volume_history)
    avg = np.mean(v[-10:])
    return (v[-1] / avg) <= 3.5 if avg > 0 else True

# ════════════════════════════════════════════════
#   MASTER SIGNAL COMBINER
# ════════════════════════════════════════════════
def combine_signals(prob):
    regime = detect_regime()
    weights = get_live_weights()

    if regime == "volatile":
        for k in ("rsi", "ema", "squeeze"):
            weights[k] = round(max(WEIGHT_MIN, min(WEIGHT_MAX, weights[k] * 0.6)), 3)

    results = {
        'displacement': get_displacement_signal(),
        'order_book'  : get_order_book_signal(),
        'vpin'        : get_vpin_signal(),
        'rsi'         : get_rsi_signal(),
        'momentum'    : get_momentum_signal(),
        'ema'         : get_ema_signal(),
        'funding_rate': get_funding_signal(),
        'polymarket'  : get_poly_signal(prob),
        'squeeze'     : get_squeeze_signal(),
    }

    up_score = down_score = 0.0
    up_count = down_count = 0
    for name, (d, _) in results.items():
        w = weights.get(name, 1.0)
        if d ==  1:
            up_score   += w
            up_count   += 1
        if d == -1:
            down_score += w
            down_count += 1

    total = up_score + down_score
    if total == 0:
        return None, 0, results, 0, 0.0, regime

    if up_score >= down_score:
        direction   = 'UP'
        win_score   = up_score
        win_count   = up_count
        score_ratio = up_score / total
    else:
        direction   = 'DOWN'
        win_score   = down_score
        win_count   = down_count
        score_ratio = down_score / total

    if win_count < MIN_SIGNALS:
        return None, 0, results, win_count, round(win_score, 2), regime

    conf  = 42
    conf += win_count   * 7
    conf += score_ratio * 18
    conf += win_score   * 2.5

    target = 1 if direction == 'UP' else -1

    # Displacement is the strongest predictor — if it agrees, big boost.
    disp_vote = results['displacement'][0]
    if disp_vote == target:
        conf += 12
    elif disp_vote != 0 and disp_vote != target:
        conf -= 15

    if results['order_book'][0]   == target: conf += 5
    if results['vpin'][0]         == target: conf += 4
    if results['funding_rate'][0] == target: conf += 3
    if results['polymarket'][0]   == target: conf += 3
    if results['order_book'][0]  != 0 and results['order_book'][0]  != target: conf -= 6
    if results['vpin'][0]        != 0 and results['vpin'][0]        != target: conf -= 4

    if (regime == "trend_up" and direction == "UP") or \
       (regime == "trend_down" and direction == "DOWN"):
        conf += 4

    confidence = round(min(94, max(0, conf)))
    return direction, confidence, results, win_count, round(win_score, 2), regime

# ════════════════════════════════════════════════
#   BINANCE WEBSOCKET
# ════════════════════════════════════════════════
def on_btc_message(ws, message):
    try:
        k     = json.loads(message)['k']
        price = float(k['c'])
        vol   = float(k['v'])
        current_price[0]  = price
        current_volume[0] = vol
        if k['x']:
            with lock:
                price_history.append(price)
                volume_history.append(vol)
    except:
        pass

def on_ws_error(ws, err):
    print(f"  [WS Error] {err}")

def on_ws_close(ws, *a):
    print("  [WS] Disconnected — reconnecting…")
    time.sleep(5)
    start_websocket()

def on_ws_open(ws, *a):
    print("  [WS] ✅ Connected to Binance live BTC feed")

def start_websocket():
    ws = websocket.WebSocketApp(
        "wss://stream.binance.com:9443/ws/btcusdt@kline_1m",
        on_message=on_btc_message,
        on_error=on_ws_error,
        on_close=on_ws_close,
        on_open=on_ws_open
    )
    threading.Thread(
        target=lambda: ws.run_forever(ping_interval=20, ping_timeout=10),
        daemon=True,
    ).start()

# ════════════════════════════════════════════════
#   PREDICTION TRACKING
# ════════════════════════════════════════════════
def save_prediction(direction, confidence, regime, price, n_signals, signals,
                    *, market_slug="", poly_prob=0.5, bucket_price=0.0):
    votes = {
        "order_book":   int(signals["order_book"][0]),
        "vpin":          int(signals["vpin"][0]),
        "rsi":           int(signals["rsi"][0]),
        "momentum":     int(signals["momentum"][0]),
        "ema":           int(signals["ema"][0]),
        "funding_rate":  int(signals["funding_rate"][0]),
        "polymarket":   int(signals["polymarket"][0]),
        "squeeze":      int(signals["squeeze"][0]),
    }
    db.execute(
        "INSERT INTO predictions "
        "(ts,direction,confidence,regime,price,signals,"
        " sig_ob, sig_vpin, sig_rsi, sig_mom, sig_ema, sig_fund,"
        " sig_poly, sig_squeeze, market_slug, poly_prob, bucket_price) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            time.time(), direction, confidence, regime, price, n_signals,
            votes["order_book"], votes["vpin"], votes["rsi"], votes["momentum"],
            votes["ema"], votes["funding_rate"],
            votes["polymarket"], votes["squeeze"],
            market_slug, poly_prob, bucket_price,
        )
    )
    db.commit()

def _fetch_gamma_resolution(slug):
    """Ask Gamma API for a settled market's winning outcome label."""
    if not slug:
        return None
    try:
        r = requests.get(
            "https://gamma-api.polymarket.com/markets",
            params={"slug": slug},
            timeout=8,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        markets = data if isinstance(data, list) else data.get("markets", [])
        if not markets:
            return None
        m = markets[0]
        # resolved=True  and  winner_label in outcomes
        if not m.get("resolved") and str(m.get("resolved")).lower() != "true":
            return None
        outcomes = m.get("outcomes", [])
        prices = m.get("outcomePrices", [])
        if outcomes and prices:
            for i, p in enumerate(prices):
                if float(p) >= 0.99:
                    return str(outcomes[i]).upper()
        return None
    except Exception:
        return None


def resolve_predictions():
    rows = db.execute(
        "SELECT id, direction, price, market_slug, bucket_price,"
        " sig_ob, sig_vpin, sig_rsi, sig_mom, sig_ema, sig_fund,"
        " sig_poly, sig_squeeze "
        "FROM predictions "
        "WHERE resolved=0 AND ts<?",
        (time.time() - 360,),
    ).fetchall()

    updated_any = False
    for row in rows:
        (pid, d, old, slug, bp,
         sig_ob, sig_vpin, sig_rsi, sig_mom, sig_ema, sig_fund,
         sig_poly, sig_squeeze) = row

        # --- resolve via Gamma (authoritative) ---
        actual = None
        gamma_winner = _fetch_gamma_resolution(slug)
        if gamma_winner:
            if "UP" in gamma_winner or "YES" in gamma_winner or "HIGHER" in gamma_winner:
                actual = "UP"
            elif "DOWN" in gamma_winner or "NO" in gamma_winner or "LOWER" in gamma_winner:
                actual = "DOWN"

        # --- fallback: bucket_price vs current price ---
        if actual is None:
            ref = bp if bp and bp > 0 else old
            if ref and ref > 0 and current_price[0] > 0:
                actual = "UP" if current_price[0] >= ref else "DOWN"

        if actual is None:
            continue

        outcome_correct = (actual == d)
        outcome = "CORRECT \u2705" if outcome_correct else "WRONG \u274c"

        db.execute(
            "UPDATE predictions SET outcome=?, resolved=1 WHERE id=?",
            (outcome, pid),
        )

        sig_votes = {
            "order_book":   sig_ob,
            "vpin":         sig_vpin,
            "rsi":          sig_rsi,
            "momentum":     sig_mom,
            "ema":          sig_ema,
            "funding_rate": sig_fund,
            "polymarket":   sig_poly,
            "squeeze":      sig_squeeze,
        }
        update_signal_weights(d, sig_votes, outcome_correct)
        updated_any = True

    if updated_any:
        db.commit()
        total_resolved = db.execute(
            "SELECT COUNT(*) FROM predictions WHERE resolved=1"
        ).fetchone()[0]
        if total_resolved and total_resolved % 20 == 0:
            auto_tune_threshold()

def get_stats():
    row = db.execute("""
        SELECT COUNT(*),
               SUM(CASE WHEN outcome LIKE 'CORRECT%' THEN 1 ELSE 0 END)
        FROM (SELECT * FROM predictions WHERE resolved=1
              ORDER BY id DESC LIMIT 50)
    """).fetchone()
    if not row or not row[0]:
        return None, None
    return row[0], round(row[1]/row[0]*100, 1)

def get_regime_breakdown():
    return db.execute("""
        SELECT regime, COUNT(*) as total,
               SUM(CASE WHEN outcome LIKE 'CORRECT%'
                   THEN 1 ELSE 0 END) as correct
        FROM predictions WHERE resolved=1
        GROUP BY regime ORDER BY total DESC
    """).fetchall()

# ════════════════════════════════════════════════
#   DISPLAY
# ════════════════════════════════════════════════
def direction_arrow(d):
    if d ==  1: return "▲ UP  "
    if d == -1: return "▼ DOWN"
    return "── neu"

def confidence_bar(conf):
    filled = int(conf / 10)
    return "█" * filled + "░" * (10 - filled)

def check_env():
    ok = True
    pk = poly_private_key()
    fd = poly_funder()
    if not pk:
        print("  ❌ POLY_PRIVATE_KEY missing"); ok = False
    else:
        print("  ✅ POLY_PRIVATE_KEY loaded")
    if not fd:
        print("  ❌ POLY_FUNDER missing"); ok = False
    else:
        print("  ✅ POLY_FUNDER loaded")
    if not POLY_API_KEY:
        print("  ⚠️  POLY_API_KEY missing (optional)")
    else:
        print("  ✅ POLY_API_KEY loaded")
    print(f"  ℹ️  POLY signature type: {poly_sig_type_int()}")
    return ok

def print_header():
    print("\n" + "═"*62)
    print("  ₿  BTC / POLYMARKET SIGNAL AGENT  v4.0  ₿")
    print("═"*62)
    print(f"  Mode      : {'⚠️  LIVE BETTING' if not DRY_RUN else '🟡 DRY RUN (no real bets)'}")
    print(f"  Bet size  : ${BET_AMOUNT:.2f}  |  "
          f"Min confidence: {MIN_CONFIDENCE}%  |  "
          f"Min signals: {MIN_SIGNALS}")
    print(f"  Edge gate : {EDGE_MARGIN:.0%} margin  |  "
          f"Window: {SAFE_WINDOW_MIN}-{SAFE_WINDOW_MAX}s")
    print(f"  Signals   : Displacement · Order book · VPIN · RSI")
    print(f"              Momentum · EMA · Funding · Polymarket · Squeeze")
    print("═"*62)
    print("  Checking credentials…")
    env_ok = check_env()
    if env_ok:
        print("  Checking Polymarket account access…")
        check_polymarket_account_access()
    print("═"*62 + "\n")

# ════════════════════════════════════════════════
#   MAIN LOOP
# ════════════════════════════════════════════════
def main():
    print_header()
    print("[1/3] Connecting to Binance…")
    start_websocket()
    time.sleep(4)
    print("[2/3] Warming up — need ~2 minutes of candle data…")
    print("[3/3] Running. Press Ctrl+C to stop.\n")

    last_bet_time = 0
    bet_cooldown  = 180
    last_slug     = ""
    prev_bucket_ts = 0

    while True:
        try:
            now_ts       = int(time.time())
            now          = datetime.now().strftime('%H:%M:%S')
            current_slug = get_current_slug()
            secs_left    = get_market_seconds_left()
            bucket_ts    = (now_ts // 300) * 300

            # ── Record bucket start price when a new 5-min window begins ──
            if bucket_ts != prev_bucket_ts:
                btc_snap = current_price[0]
                if btc_snap > 0:
                    bucket_start_price[0] = btc_snap
                    bucket_start_ts[0] = bucket_ts
                    print(f"\n  [Bucket] New window {bucket_ts}  "
                          f"start price ${btc_snap:,.2f}")
                prev_bucket_ts = bucket_ts

            market = find_btc_market()
            prob   = get_yes_probability(market) if market else 0.5
            with lock:
                prob_history.append(prob)

            btc = current_price[0]
            with lock:
                ph = len(price_history)

            if current_slug != last_slug:
                if market:
                    q = market.get('question', current_slug)[:55]
                    mslug = market.get('slug', 'n/a')
                    print(f"\n  [Polymarket] \u2705 {q}")
                    print(f"  [Polymarket] slug: {mslug}")
                    print(f"  [Polymarket] UP prob: {prob:.1%}"
                          f"  |  {secs_left}s remaining")
                else:
                    print(f"\n  [Polymarket] \u23f3 {current_slug} — searching…")
                last_slug = current_slug

            if ph < 14:
                bar = "\u2588" * ph + "\u2591" * (14 - ph)
                print(f"[{now}] Warming up [{bar}] {ph}/14  "
                      f"BTC=${btc:,.0f}  "
                      f"Poly={prob:.0%}  "
                      f"{secs_left}s left")
                time.sleep(20)
                continue

            # ── Timing gates ──
            if secs_left > SAFE_WINDOW_MAX:
                disp_pct, _ = get_displacement_info()
                print(f"[{now}] Observing… {secs_left}s left  "
                      f"BTC=${btc:,.2f}  "
                      f"disp={disp_pct:+.4f}%  "
                      f"Poly={prob:.1%}")
                time.sleep(10)
                continue

            if secs_left < SAFE_WINDOW_MIN:
                print(f"[{now}] Window closing ({secs_left}s) — waiting for next…")
                time.sleep(10)
                continue

            # ── Compute signals ──
            direction, confidence, signals, \
                n_agree, w_score, regime = combine_signals(prob)

            resolve_predictions()
            total, winrate = get_stats()
            wr_str = f"{winrate}% ({total} resolved)" \
                     if winrate else "building…"

            rsi = calc_rsi()
            disp_pct, vol_5m = get_displacement_info()
            mkt_ok = f"\u2705 {secs_left}s" if market else "\u274c searching"

            print(f"\n[{now}] {'\u2500' * 50}")
            print(f"  BTC          : ${btc:>10,.2f}   RSI: {rsi:.1f}")
            print(f"  Bucket start : ${bucket_start_price[0]:>10,.2f}   "
                  f"Disp: {disp_pct:+.4f}%   Vol5m: {vol_5m:.4f}%")
            print(f"  Polymarket   : {prob:.1%} UP  \u2502  Market: {mkt_ok}")
            print(f"  Win rate     : {wr_str}")
            print(f"  \u2500\u2500 9 Signals {'\u2500' * 34}")

            labels = [
                ('displacement', 'Displacement'),
                ('order_book',   'Order book  '),
                ('vpin',         'VPIN        '),
                ('rsi',          'RSI         '),
                ('momentum',     'Momentum    '),
                ('ema',          'EMA cross   '),
                ('funding_rate', 'Funding rate'),
                ('polymarket',   'Polymarket  '),
                ('squeeze',      'Vol squeeze '),
            ]
            live_weights = get_live_weights()
            for key, label in labels:
                d, v = signals[key]
                print(f"  {label}: {direction_arrow(d)}  "
                      f"(val={v:.4f}, "
                      f"weight={live_weights.get(key, 1.0):.2f})")

            print(f"  {'\u2500' * 48}")
            print(f"  Agreeing : {n_agree}/9  "
                  f"Score: {w_score:.1f}  "
                  f"Direction: {direction or 'NONE'}  "
                  f"Conf: {confidence}%")
            print(f"  [{confidence_bar(confidence)}]")

            cooldown_ok = (time.time() - last_bet_time) > bet_cooldown
            effective_threshold = get_effective_threshold()
            price_ok  = is_price_stable()
            volume_ok = is_volume_normal()

            # ── Displacement gate: BTC must have moved meaningfully ──
            disp_ok = abs(disp_pct) >= MIN_DISPLACEMENT_PCT

            # ── Edge gate: our estimated prob must beat market price by EDGE_MARGIN ──
            edge_ok = False
            edge_info = ""
            if direction:
                est_p, impl_p, edge = compute_edge(
                    direction, prob, disp_pct, secs_left, vol_5m
                )
                edge_ok = edge >= EDGE_MARGIN
                edge_info = (
                    f"P(win)={est_p:.1%} vs implied={impl_p:.1%}  "
                    f"edge={edge:+.1%}"
                )
                print(f"  Edge check : {edge_info}  "
                      f"{'PASS' if edge_ok else 'SKIP'}")

            if not disp_ok and direction:
                print(f"  Disp check : |{disp_pct:.4f}%| < {MIN_DISPLACEMENT_PCT}% — "
                      f"too flat, SKIP")

            should_bet = (
                direction
                and confidence >= effective_threshold
                and cooldown_ok
                and price_ok
                and volume_ok
                and disp_ok
                and edge_ok
            )

            if should_bet:
                mslug = market.get("slug", "") if market else ""

                print(f"\n  \u2554{'\u2550' * 52}\u2557")
                print(f"  \u2551  \u2605\u2605 SIGNAL: {direction:<4} "
                      f"@ {confidence}% confidence \u2605\u2605      \u2551")
                print(f"  \u2551  {n_agree}/9 signals  "
                      f"|  Score: {w_score:.1f}  "
                      f"|  {secs_left}s left          \u2551")
                print(f"  \u2551  {edge_info:<50}\u2551")
                print(f"  \u255a{'\u2550' * 52}\u255d")

                save_prediction(
                    direction, confidence, regime,
                    btc, n_agree, signals,
                    market_slug=mslug,
                    poly_prob=prob,
                    bucket_price=bucket_start_price[0],
                )

                if not DRY_RUN and market:
                    place_bet(market, direction, BET_AMOUNT)
                elif not DRY_RUN and not market:
                    print("  [Bet] Skipped — Polymarket market not found")
                else:
                    print(f"  [DRY RUN] Would bet "
                          f"${BET_AMOUNT} on {direction}")

                last_bet_time = time.time()

                print("\n  \u2500\u2500 Regime breakdown \u2500\u2500")
                for reg, tot, cor in get_regime_breakdown():
                    pct = round(cor / tot * 100, 1) if tot else 0
                    print(f"  {reg:<26}: {cor}/{tot} ({pct}%)")

            time.sleep(30)

        except KeyboardInterrupt:
            print("\n\n[Bot] Stopped.")
            total, winrate = get_stats()
            if total:
                print(f"  Total predictions : {total}")
                print(f"  Win rate          : {winrate}%")
                for reg, tot, cor in get_regime_breakdown():
                    pct = round(cor / tot * 100, 1) if tot else 0
                    print(f"  {reg:<26}: {cor}/{tot} ({pct}%)")
            print("Goodbye!")
            break
        except Exception as e:
            print(f"  [Error] {e}")
            time.sleep(15)


def verify_polymarket_only():
    """Auth + balance check only (no order)."""
    print("\n" + "═" * 50)
    print("  Polymarket verify — no order will be placed")
    print("═" * 50 + "\n")
    ok = check_env()
    if not ok:
        return False
    return check_polymarket_account_access()


def run_test_bet_once(direction="UP", *, skip_confirm=False):
    """
    Place one small REAL order on the current BTC 5m market, then return.
    Set TEST_BET_USD in .env (default 1.0). Uses force_live=True even if DRY_RUN.
    """
    print("\n" + "!" * 58)
    print("  TEST BET — places a REAL Polymarket order (costs real funds).")
    print("!" * 58)

    try:
        amt = float(first_env("TEST_BET_USD", default="1.0"))
    except (ValueError, TypeError):
        amt = 1.0
    amt = max(0.5, min(amt, 50.0))

    if not poly_private_key() or not poly_funder():
        print("\n  ❌ POLY_PRIVATE_KEY or POLY_FUNDER missing — fix .env first.")
        return False

    if not skip_confirm:
        print(f"\n  Amount: ${amt:.2f} USDC (collateral)  |  Side: BUY {direction}")
        print("  (Change amount with TEST_BET_USD in .env)\n")
        reply = input("  Type YES and press Enter to place this order, or anything else to abort: ")
        if reply.strip().upper() != "YES":
            print("  Aborted.")
            return False

    print("\n  [1/3] Environment…")
    check_env()

    print("\n  [2/3] Polymarket access…")
    if not check_polymarket_account_access():
        return False

    print("\n  [3/3] Market + order…")
    market = find_btc_market()
    if not market:
        print("  ❌ No active BTC 5m market found right now.")
        return False

    q = market.get("question", "")[:75]
    print(f"  Market: {q}")
    ok = place_bet(market, direction.upper(), amt, force_live=True)
    if ok:
        print("\n  ✅ Test order submitted — check Polymarket / your positions.")
    else:
        print("\n  ❌ Test order failed — read errors above (balance, allowance, liquidity, etc.).")
    return bool(ok)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="BTC / Polymarket signal bot",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Only check .env + Polymarket auth/balance (no order).",
    )
    parser.add_argument(
        "--test-bet",
        action="store_true",
        help="Place ONE small real order then exit (see TEST_BET_USD in .env).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="With --test-bet, skip the YES confirmation (use only if you know the risk).",
    )
    parser.add_argument(
        "--direction",
        choices=("UP", "DOWN"),
        default="UP",
        help="With --test-bet, which outcome token to buy (default UP).",
    )
    args = parser.parse_args()

    if args.verify:
        raise SystemExit(0 if verify_polymarket_only() else 1)

    if args.test_bet:
        raise SystemExit(
            0 if run_test_bet_once(args.direction, skip_confirm=args.yes) else 1
        )

    main()