#!/usr/bin/env python3
"""
Altcoin volatility scanner v3  (data: Coinalyze free API  ->  alerts: Telegram)

Modes (python scanner.py <mode>):
  universe-auto  daily coin-list refresh: quick (re-ranks saved pool, ~5 min) or full (weekly, ~40 min)
  universe       force a full coin-list rebuild;   universe-quick  force a quick refresh
  scan           hourly scan, sends Telegram alerts when something qualifies
  scan-dry-run   same as scan but prints the message instead of sending, changes no state
  diagnose       tests Telegram and Coinalyze separately and prints PASS/FAIL with hints

Secrets (GitHub -> Settings -> Secrets -> Actions):
  COINALYZE_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
"""
from __future__ import annotations

import csv
import html
import json
import math
import os
import re
import sys
import time
import datetime as dt
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd
import requests

BASE_URL = "https://api.coinalyze.net/v1"
TG_URL = "https://api.telegram.org"
UTC = dt.timezone.utc

EXCLUDED_BASES = {
    "BTC", "ETH",
    "USDT", "USDC", "DAI", "FDUSD", "TUSD", "USDE", "USDD", "PYUSD", "USDP", "BUSD", "EURI", "RLUSD",
    "WBTC", "WETH", "STETH", "WSTETH", "WEETH", "CBBTC", "CBETH", "RETH", "BTCB",
}

SCANNER_VERSION = "3.0"

# Contracts on perp venues that are NOT crypto coins. Deliberately conservative: only tickers that clearly are not
# crypto (ambiguous ones like SPX = SPX6900 or STX = Stacks are left out). The user can add more in data/exclude.txt.
NON_CRYPTO_BASES = {
    "XAU", "XAG", "XPT", "XPD", "XCU", "CL", "BZ", "WTI", "BRENT", "NATGAS",
    "SPY", "QQQ", "NDX", "DJI", "DXY", "EURUSD", "GBPUSD", "USDJPY", "AUDUSD", "IWM", "ARKK", "GLD", "SLV", "TLT",
    "AAPL", "MSFT", "GOOGL", "GOOG", "AMZN", "NVDA", "TSLA", "AMD", "INTC", "SNDK", "SPCX", "CRCL", "MSTR", "PLTR",
    "NFLX", "BABA", "TSM", "ORCL", "AVGO", "SKHYNIX", "SAMSUNG", "SMCI", "MRVL", "JPM", "WMT", "XOM", "CVX", "PYPL",
    "SHOP", "UBER", "AMAT", "ASML", "LRCX", "QCOM", "WDC", "DELL", "IBM", "CSCO", "ADBE", "RBLX", "LLY", "UNH", "PFE",
    "MRNA",
}
NON_CRYPTO_CATEGORY_WORDS = ("stock", "equit", "commod", "forex", "fx", "index", "indic", "etf", "metal", "energy", "bond", "currenc")

# scoring weights (sum to 1 inside each block). These are starting points, tune from data/scan_log.csv.
SETUP_W = {"oi4h": 0.25, "oi1d": 0.15, "compression": 0.15, "crowding": 0.15, "cvd": 0.15, "stealth": 0.15}
TRIGGER_W = {"oi_accel": 0.35, "vol_exp": 0.25, "cvd_1h": 0.20, "range_exp": 0.20}
SETUP_MIN_FOR_TIER = 0.50          # untuned starting point - adjust after a few weeks of data/scan_log.csv
TRIGGER_MIN_FOR_IMMINENT = 0.45   # v2: was 0.30 (too many IMMINENT)
MIN_1H_WAKE = 2.0                 # v2: IMMINENT also needs 1h volume OR 1h range >= 2x normal
TIER_RANK = {"IMMINENT": 0, "BUILDING": 1, "WATCH": 2}


# ----------------------------------------------------------------------------- config / errors
def _e(name, default):
    v = os.environ.get(name)
    return default if v is None or str(v).strip() == "" else v


def load_cfg():
    return {
        "data_dir": Path(_e("SCANNER_DATA_DIR", "data")),
        "universe_size": int(_e("UNIVERSE_SIZE", "100")),
        "stage_b_n": int(_e("STAGE_B_N", "20")),
        "top_k": int(_e("TOP_K", "7")),
        "min_turnover": float(_e("MIN_TURNOVER_USD", "2000000")),
        "min_universe_oi": float(_e("MIN_UNIVERSE_OI_USD", "3000000")),
        "lookback_days": int(_e("LOOKBACK_DAYS", "30")),
        "min_bars": int(_e("MIN_BARS", "300")),
        "calls_per_min": int(_e("CALLS_PER_MIN", "36")),
        "cooldown_h": float(_e("COOLDOWN_HOURS", "4")),
        "max_stale_h": float(_e("MAX_STALE_HOURS", "2.5")),
        "batch": int(_e("BATCH_SIZE", "12")),  # 3 x 12 = 36 calls per minute
        "pool_size": int(_e("POOL_SIZE", "150")),
        "max_imminent": int(_e("MAX_IMMINENT", "3")),
        "liq": str(_e("LIQ_ENABLED", "1")).strip().lower() not in ("0", "false", "no"),
        "extra_exclude": _e("EXTRA_EXCLUDE", ""),
        "full_every_h": float(_e("FULL_REFRESH_HOURS", "47")),
        "bt_coins": int(_e("BT_COINS", "60")),
        "bt_step_h": int(_e("BT_STEP_H", "3")),
    }


class ApiError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class TelegramError(Exception):
    pass


class FatalError(Exception):
    pass


class Skip(Exception):
    """A single coin is skipped (never fatal)."""


def log(*a):
    print(*a, flush=True)


# ----------------------------------------------------------------------------- rate limiter + client
class RateLimiter:
    """Sliding 60s window. Coinalyze: 40 calls/min per key, each symbol in a multi-symbol call counts."""

    def __init__(self, per_min, clock=time.monotonic, sleep=time.sleep):
        if per_min < 20:
            raise ValueError("calls_per_min must be >= 20")
        self.per_min, self.clock, self.sleep = per_min, clock, sleep
        self.stamps = deque()

    def acquire(self, n=1):
        n = min(n, self.per_min)
        while True:
            now = self.clock()
            while self.stamps and now - self.stamps[0] >= 60:
                self.stamps.popleft()
            if len(self.stamps) + n <= self.per_min:
                for _ in range(n):
                    self.stamps.append(now)
                return
            self.sleep(max(60 - (now - self.stamps[0]) + 0.05, 0.05))


class Coinalyze:
    def __init__(self, key, limiter=None, session=None, sleep=time.sleep, batch=10):
        self.key = key
        self.limiter = limiter or RateLimiter(36)
        self.s = session or requests.Session()
        self.sleep = sleep
        self.batch = batch
        self.calls = 0

    def get(self, path, params=None, cost=1, retries=4):
        if not self.key:
            raise ApiError("COINALYZE_API_KEY is empty - add it as a GitHub secret", 401)
        last = "unknown"
        for attempt in range(retries + 1):
            self.limiter.acquire(cost)
            self.calls += cost
            try:
                r = self.s.get(BASE_URL + path, params=params or {}, headers={"api_key": self.key}, timeout=30)
            except requests.RequestException as e:
                last = f"network error: {type(e).__name__}"
                self.sleep(min(2 ** attempt, 20))
                continue
            sc = r.status_code
            if sc == 429:
                try:
                    ra = float(r.headers.get("Retry-After", 15))
                except (TypeError, ValueError):
                    ra = 15.0
                last = "rate limited (429)"
                self.sleep(min(ra + 1, 70))
                continue
            if sc >= 500:
                last = f"server error {sc}"
                self.sleep(min(2 ** attempt * 2, 30))
                continue
            if sc in (401, 403):
                raise ApiError(f"Coinalyze rejected the API key (HTTP {sc})", sc)
            if sc >= 400:
                raise ApiError(f"HTTP {sc}: {r.text[:200]}", sc)
            try:
                return r.json()
            except ValueError:
                raise ApiError(f"Coinalyze returned non-JSON (HTTP {sc}): {r.text[:120]!r}", sc)
        raise ApiError(f"gave up after {retries + 1} attempts ({last})")

    def fetch_history(self, endpoint, symbols, interval, t_from, t_to, extra=None):
        """Returns ({symbol: history_list}, {symbol: error_string}). A bad symbol never kills the batch."""
        out, errs = {}, {}

        def one(chunk):
            params = {"symbols": ",".join(chunk), "interval": interval, "from": int(t_from), "to": int(t_to)}
            params.update(extra or {})
            data = self.get(endpoint, params, cost=len(chunk))
            if not isinstance(data, list):
                raise ApiError(f"unexpected response shape {type(data).__name__}")
            for item in data:
                if isinstance(item, dict) and "symbol" in item:
                    out[item["symbol"]] = item.get("history") or []

        for i in range(0, len(symbols), self.batch):
            chunk = list(symbols[i:i + self.batch])
            try:
                one(chunk)
            except ApiError as e:
                if e.status in (401, 403):
                    raise
                if len(chunk) > 1:  # isolate the bad symbol
                    for s in chunk:
                        try:
                            one([s])
                        except ApiError as e2:
                            if e2.status in (401, 403):
                                raise
                            errs[s] = str(e2)
                else:
                    errs[chunk[0]] = str(e)
        return out, errs


# ----------------------------------------------------------------------------- math helpers
def clip01(x):
    return float(min(max(x, 0.0), 1.0))


def zpos(z, cap=4.0):
    """0..1 score for a z-score where only 'high' matters. NaN -> 0."""
    if z is None or (isinstance(z, float) and math.isnan(z)):
        return 0.0
    return clip01(max(z, 0.0) / cap)


def zabs(z, cap=4.0):
    if z is None or (isinstance(z, float) and math.isnan(z)):
        return 0.0
    return clip01(abs(z) / cap)


def rz(series, min_hist=20, cap=5.0, min_scale=0.0):
    """Robust z of the LAST value vs the earlier history (median/MAD). NaN if not enough history."""
    s = pd.Series(series, dtype=float).replace([np.inf, -np.inf], np.nan)
    if len(s) < 2 or pd.isna(s.iloc[-1]):
        return float("nan")
    hist = s.iloc[:-1].dropna()
    if len(hist) < min_hist:
        return float("nan")
    med = float(hist.median())
    scale = 1.4826 * float((hist - med).abs().median())
    if scale < 1e-12:
        scale = float(hist.std()) if len(hist) > 1 else 0.0
    if not math.isfinite(scale):
        scale = 0.0
    scale = max(scale, min_scale)  # v2: a quiet metric must move by a REAL amount to score as extreme
    last = float(s.iloc[-1])
    if not scale or scale < 1e-12:
        return 0.0 if abs(last - med) < 1e-9 else float(np.sign(last - med) * cap)
    return float(np.clip((last - med) / scale, -cap, cap))


def pct_rank(series, min_hist=30):
    s = pd.Series(series, dtype=float).replace([np.inf, -np.inf], np.nan)
    if len(s) < 2 or pd.isna(s.iloc[-1]):
        return float("nan")
    hist = s.iloc[:-1].dropna()
    if len(hist) < min_hist:
        return float("nan")
    last = s.iloc[-1]
    return float((hist < last).mean() + 0.5 * (hist == last).mean())


# ----------------------------------------------------------------------------- data frames
def hist_to_df(hist, fields):
    if not hist:
        return pd.DataFrame(columns=fields, dtype=float)
    d = pd.DataFrame(hist)
    if "t" not in d.columns:
        return pd.DataFrame(columns=fields, dtype=float)
    d["t"] = pd.to_datetime(pd.to_numeric(d["t"], errors="coerce"), unit="s", utc=True)
    d = d.dropna(subset=["t"]).drop_duplicates("t").set_index("t").sort_index()
    for f in fields:
        if f not in d.columns:
            d[f] = np.nan
    return d[fields].apply(pd.to_numeric, errors="coerce")


def build_frame(px_hist, oi_hist, fr_hist, ls_hist, now, denom=None, max_stale_h=2.5, spot_hist=None):
    px = hist_to_df(px_hist, ["o", "h", "l", "c", "v", "bv"])
    if px.empty:
        raise Skip("no OHLCV data")
    px = px[px.index + pd.Timedelta(hours=1) <= pd.Timestamp(now)]  # drop the still-forming candle
    if px.empty:
        raise Skip("no completed candles")
    df = px.copy()
    df["oi"] = hist_to_df(oi_hist, ["c"])["c"].reindex(df.index).ffill(limit=3)
    df["fund"] = hist_to_df(fr_hist, ["c"])["c"].reindex(df.index).ffill(limit=8) if fr_hist else np.nan
    df["lsr"] = hist_to_df(ls_hist, ["r"])["r"].reindex(df.index).ffill(limit=3) if ls_hist else np.nan
    if spot_hist:  # spot buy/sell volume on the same hourly grid (for spot-vs-futures CVD)
        sp = hist_to_df(spot_hist, ["v", "bv"])
        df["sv"] = sp["v"].reindex(df.index)
        df["sbv"] = sp["bv"].reindex(df.index)
    if str(denom or "").upper() == "USD":  # make OI coin-denominated so price moves don't fake a build-up
        df["oi"] = df["oi"] / df["c"]
    age_h = (pd.Timestamp(now) - (df.index[-1] + pd.Timedelta(hours=1))).total_seconds() / 3600
    if age_h > max_stale_h:
        raise Skip(f"stale data (last candle ended {age_h:.1f}h ago)")
    return df


def agg_bars(df, k, last_ts):
    """k-hour bars aligned so the newest bar ends exactly at the newest complete hour (always full)."""
    origin = last_ts - pd.Timedelta(hours=k - 1)
    g = df.resample(f"{k}h", origin=origin, closed="left", label="left")
    cols = {
        "o": g["o"].first(), "h": g["h"].max(), "l": g["l"].min(), "c": g["c"].last(),
        "v": g["v"].sum(min_count=1), "bv": g["bv"].sum(min_count=1),
        "oi": g["oi"].last(), "n": g["c"].count(),
    }
    if "sv" in df.columns:
        cols["sv"] = g["sv"].sum(min_count=1)
        cols["sbv"] = g["sbv"].sum(min_count=1)
    out = pd.DataFrame(cols)
    return out[out["n"] == k]


def prelim_oi_score(oi_hist):
    """Stage A: cheap OI-only build-up score (0..1) for ranking the whole universe."""
    d = hist_to_df(oi_hist, ["c"])["c"].dropna()
    if len(d) < 200:
        raise Skip("short OI history")
    last_ts = d.index[-1]
    frame = pd.DataFrame({"o": d, "h": d, "l": d, "c": d, "v": 1.0, "bv": 0.5, "oi": d})
    h4 = agg_bars(frame, 4, last_ts)
    d1 = agg_bars(frame, 24, last_ts)
    z4 = rz(h4["oi"].pct_change(), min_scale=0.008)
    z1 = rz(d1["oi"].pct_change(), min_hist=14, min_scale=0.02)
    z2 = rz(d.pct_change(2), min_scale=0.005)
    comp = [zpos(z4), zpos(z1), zpos(z2)]
    return 0.4 * comp[0] + 0.3 * comp[1] + 0.3 * comp[2], {"oi4_z": z4, "oi1d_z": z1, "oi2h_z": z2}


# ----------------------------------------------------------------------------- scoring
def cvd_mode(fut_z, spot_z):
    """Reads futures CVD vs spot CVD (4H z-scores). Leveraged futures-only flow is fragile; spot-backed flow is sturdier."""
    if spot_z is None or math.isnan(spot_z):
        return "spot n/a"
    if math.isnan(fut_z):
        return "no clear flow"
    f, sp = fut_z, spot_z
    if sp >= 1.0 and f <= -1.0:
        return "SPOT BUYING vs futures selling (squeeze fuel)"
    if sp <= -1.0 and f >= 1.0:
        return "SPOT SELLING vs futures buying (long-trap risk)"
    if sp >= 1.0 and f >= 1.0:
        return "spot + futures buying (confirmed)"
    if sp <= -1.0 and f <= -1.0:
        return "spot + futures selling (confirmed)"
    if f >= 1.5 and sp < 1.0:
        return "FUTURES-LED buying (leveraged, fragile)"
    if f <= -1.5 and sp > -1.0:
        return "FUTURES-LED selling (leveraged, fragile)"
    if sp >= 1.5 and f < 1.0:
        return "SPOT-LED accumulation"
    if sp <= -1.5 and f > -1.0:
        return "SPOT-LED distribution"
    return "no clear flow"


def lean_text(fund_z, lsr_z, imb4_z):
    # "Crowded" needs real evidence: one indicator at |z|>=2, or funding AND long/short ratio agreeing at |z|>=1.
    # (NaN comparisons are False, so missing data can never create a lean.)
    long_crowd = fund_z >= 2.0 or lsr_z >= 2.0 or (fund_z >= 1.0 and lsr_z >= 1.0)
    short_crowd = fund_z <= -2.0 or lsr_z <= -2.0 or (fund_z <= -1.0 and lsr_z <= -1.0)
    if long_crowd and not short_crowd:
        return "Crowded LONGS - downside flush risk"
    if short_crowd and not long_crowd:
        return "Crowded SHORTS - upside squeeze risk"
    if not math.isnan(imb4_z) and abs(imb4_z) >= 2.0:
        return "Flow buy-led (unconfirmed)" if imb4_z > 0 else "Flow sell-led (unconfirmed)"
    return "No clear lean"


def score_coin(df, cfg):
    if len(df) < cfg["min_bars"]:
        raise Skip(f"history {len(df)}h < {cfg['min_bars']}h")
    tail = df.tail(100)
    if pd.isna(df["oi"].iloc[-1]) or tail["oi"].isna().mean() > 0.10:
        raise Skip("open-interest gaps")
    if tail["c"].isna().mean() > 0.05 or tail["v"].isna().mean() > 0.05:
        raise Skip("price/volume gaps")
    if tail["bv"].isna().mean() > 0.30:
        raise Skip("no buy/sell volume (CVD impossible)")

    last_ts = df.index[-1]
    close = df["c"]
    turnover24 = float((df["v"] * df["c"]).tail(24).sum())
    if turnover24 < cfg["min_turnover"]:
        raise Skip(f"illiquid (${turnover24 / 1e6:.1f}M per 24h)")

    h4 = agg_bars(df, 4, last_ts)
    d1 = agg_bars(df, 24, last_ts)
    if len(h4) < 60 or len(d1) < 14:
        raise Skip("not enough 4H/1D bars")

    ret4 = float(close.iloc[-1] / close.iloc[-5] - 1)
    ret24 = float(close.iloc[-1] / close.iloc[-25] - 1)
    if math.isnan(ret4) or math.isnan(ret24):
        raise Skip("price NaN")

    # ---- 1D / 4H positioning
    oi4_chg, oi1d_chg = h4["oi"].pct_change(), d1["oi"].pct_change()
    oi4_z, oi1d_z = rz(oi4_chg, min_scale=0.008), rz(oi1d_chg, min_hist=14, min_scale=0.02)
    oi2h_chg = df["oi"].pct_change(2)
    oi2h_z = rz(oi2h_chg, min_scale=0.005)

    vol4 = h4["v"].replace(0, np.nan)
    imb4 = ((2 * h4["bv"] - h4["v"]) / vol4)
    imb4_z = rz(imb4, min_scale=0.03)
    v3 = df["v"].rolling(3).sum().replace(0, np.nan)
    imb3h = (2 * df["bv"].rolling(3).sum() - df["v"].rolling(3).sum()) / v3
    imb3_z = rz(imb3h, min_scale=0.04)
    spot_imb4_z = spot_imb3_z = float("nan")
    if ("sv" in df.columns and "sv" in h4.columns and df["sv"].tail(100).notna().mean() >= 0.7
            and df["sbv"].tail(100).notna().mean() >= 0.7):
        simb4 = (2 * h4["sbv"] - h4["sv"]) / h4["sv"].replace(0, np.nan)
        spot_imb4_z = rz(simb4, min_scale=0.03)
        sv3 = df["sv"].rolling(3).sum().replace(0, np.nan)
        simb3 = (2 * df["sbv"].rolling(3).sum() - df["sv"].rolling(3).sum()) / sv3
        spot_imb3_z = rz(simb3, min_scale=0.04)

    c4 = h4["c"]
    bbw = 4 * c4.rolling(20).std() / c4.rolling(20).mean()
    pc = c4.shift(1)
    tr4 = pd.concat([(h4["h"] - h4["l"]), (h4["h"] - pc).abs(), (h4["l"] - pc).abs()], axis=1).max(axis=1) / c4
    atr4 = tr4.rolling(14).mean()
    pr_bb, pr_atr = pct_rank(bbw), pct_rank(atr4)
    comp_parts = [1 - p for p in (pr_bb, pr_atr) if not math.isnan(p)]
    compression = float(np.mean(comp_parts)) if comp_parts else 0.0

    fund_z = rz(df["fund"], min_scale=0.01) if df["fund"].notna().sum() > 50 else float("nan")
    lsr_z = rz(df["lsr"], min_scale=0.05) if df["lsr"].notna().sum() > 50 else float("nan")
    crowd_parts = [zabs(z) for z in (fund_z, lsr_z) if not math.isnan(z)]
    crowding = float(np.mean(crowd_parts)) if crowd_parts else 0.0

    stealth = clip01(1 - abs(ret24) / 0.10)
    price_dir = 0 if abs(ret4) < 0.002 else int(np.sign(ret4))
    cvd_dir = 0 if math.isnan(imb4_z) else int(np.sign(imb4.iloc[-1]))
    cvd_div = bool(price_dir != 0 and cvd_dir != 0 and cvd_dir != price_dir and not math.isnan(imb4_z) and abs(imb4_z) >= 1.0)
    sf_div = bool(not math.isnan(spot_imb4_z) and not math.isnan(imb4_z) and spot_imb4_z * imb4_z < 0
                  and abs(spot_imb4_z) >= 1.0 and abs(imb4_z) >= 1.0)  # spot and futures disagree = someone is wrong
    cvd_score = clip01(max(zabs(imb4_z), zabs(spot_imb4_z)) + (0.15 if cvd_div else 0.0) + (0.15 if sf_div else 0.0))

    setup_parts = {
        "oi4h": zpos(oi4_z), "oi1d": zpos(oi1d_z), "compression": compression,
        "crowding": crowding, "cvd": cvd_score, "stealth": stealth,
    }
    setup = sum(SETUP_W[k] * v for k, v in setup_parts.items())

    # ---- 1H trigger
    vbase = float(df["v"].iloc[-25:-1].mean())
    vol_ratio = float(df["v"].iloc[-1] / vbase) if vbase > 0 else 1.0
    trh = (df["h"] - df["l"]) / df["c"]
    trh_w = trh.clip(upper=trh.quantile(0.99))  # tame single wild wicks
    rbase = float(trh_w.iloc[-73:-1].median())
    range_ratio = float(trh.iloc[-1] / rbase) if rbase > 0 else 1.0
    trig_parts = {
        "oi_accel": zpos(oi2h_z), "vol_exp": clip01((vol_ratio - 1) / 3),
        "cvd_1h": max(zabs(imb3_z), zabs(spot_imb3_z)), "range_exp": clip01((range_ratio - 1) / 2),
    }
    trigger = sum(TRIGGER_W[k] * v for k, v in trig_parts.items())

    flags = []
    penalty = 1.0
    if abs(ret4) > 0.06 or abs(ret24) > 0.15:
        penalty = 0.5
        flags.append("LATE (already moved)")
    if not crowd_parts:
        flags.append("no funding/LSR data")
    score = 100 * (0.6 * setup + 0.4 * trigger) * penalty
    if penalty < 1.0:
        tier = "WATCH"  # a coin that already ran is never IMMINENT/BUILDING and never triggers a ping
    elif (setup >= SETUP_MIN_FOR_TIER and trigger >= TRIGGER_MIN_FOR_IMMINENT
          and (vol_ratio >= MIN_1H_WAKE or range_ratio >= MIN_1H_WAKE)):
        tier = "IMMINENT"
    elif setup >= SETUP_MIN_FOR_TIER:
        tier = "BUILDING"
    else:
        tier = "WATCH"

    fund_last = float(df["fund"].dropna().iloc[-1]) if df["fund"].notna().any() else float("nan")
    px = float(close.iloc[-1])
    levels = {"px": px, "hi24": float(df["h"].tail(24).max()), "lo24": float(df["l"].tail(24).min()),
              "hi3d": float(df["h"].tail(72).max()), "lo3d": float(df["l"].tail(72).min())}
    typ4 = float(((h4["h"] - h4["l"]) / h4["c"]).tail(60).median())
    # how big this coin's NORMAL 12h excursions are (used by the outcome tracker as the "chance" baseline)
    fwd_hi = df["h"].iloc[::-1].rolling(12, min_periods=12).max().iloc[::-1].shift(-1)
    fwd_lo = df["l"].iloc[::-1].rolling(12, min_periods=12).min().iloc[::-1].shift(-1)
    exc12 = pd.Series(np.maximum(fwd_hi / close - 1, 1 - fwd_lo / close)).replace([np.inf, -np.inf], np.nan).dropna()
    exc12_p90 = float(exc12.quantile(0.9)) if len(exc12) >= 100 else float("nan")
    f4hi = df["h"].iloc[::-1].rolling(4, min_periods=4).max().iloc[::-1].shift(-1)
    f4lo = df["l"].iloc[::-1].rolling(4, min_periods=4).min().iloc[::-1].shift(-1)
    exc4 = pd.Series(np.maximum(f4hi / close - 1, 1 - f4lo / close)).replace([np.inf, -np.inf], np.nan).dropna()
    exc4_p90 = float(exc4.quantile(0.9)) if len(exc4) >= 100 else float("nan")
    return {
        "score": float(score), "setup": float(setup), "trigger": float(trigger), "tier": tier, "flags": flags,
        "lean": lean_text(fund_z, lsr_z, imb4_z),
        "cvd_mode": cvd_mode(imb4_z, spot_imb4_z),
        "p0": px, "t0": (df.index[-1] + pd.Timedelta(hours=1)).isoformat(), "levels": levels,
        "m": {
            "oi4_chg": float(oi4_chg.iloc[-1]), "oi1d_chg": float(oi1d_chg.iloc[-1]),
            "oi4_z": oi4_z, "oi1d_z": oi1d_z, "oi2h_z": oi2h_z,
            "fund_last": fund_last, "fund_z": fund_z, "lsr_z": lsr_z,
            "imb4_z": imb4_z, "imb3_z": imb3_z, "cvd_div": cvd_div,
            "spot_imb4_z": spot_imb4_z, "spot_imb3_z": spot_imb3_z,
            "bbw_pct": pr_bb, "atr_pct": pr_atr, "ret4": ret4, "ret24": ret24,
            "vol_ratio": vol_ratio, "range_ratio": range_ratio, "turnover24": turnover24,
            "typ4": typ4, "exc12_p90": exc12_p90, "exc4_p90": exc4_p90,
        },
        "parts": {**{f"s_{k}": v for k, v in setup_parts.items()}, **{f"t_{k}": v for k, v in trig_parts.items()}},
    }


def btc_regime(df):
    if df is None or len(df) < 30:
        return {"ok": False, "text": "BTC regime unknown"}
    c = df["c"]
    r4, r24 = float(c.iloc[-1] / c.iloc[-5] - 1), float(c.iloc[-1] / c.iloc[-25] - 1)
    hard = abs(r4) >= 0.025 or abs(r24) >= 0.05
    txt = f"BTC {'MOVING HARD - alt signals noisy' if hard else 'calm'} (4h {r4 * 100:+.1f}%, 24h {r24 * 100:+.1f}%)"
    return {"ok": True, "hard": hard, "r4": r4, "r24": r24, "text": txt}


# ----------------------------------------------------------------------------- universe
def find_exchange_code(exchanges, name="bybit"):
    for e in exchanges or []:
        if str(e.get("name", "")).strip().lower() == name:
            return str(e.get("code"))
    for e in exchanges or []:
        if name in str(e.get("name", "")).lower():
            return str(e.get("code"))
    return None


def user_excludes(cfg):
    """Extra tickers to skip: one per line in data/exclude.txt (editable on GitHub) plus the EXTRA_EXCLUDE variable."""
    out = set()
    try:
        for line in (Path(cfg["data_dir"]) / "exclude.txt").read_text().splitlines():
            for x in re.split(r"[,\s]+", line.split("#", 1)[0].strip().upper()):
                if x:
                    out.add(x[:-4] if x.endswith("USDT") and len(x) > 4 else x)
    except (FileNotFoundError, OSError):
        pass
    for x in str(cfg.get("extra_exclude", "")).split(","):
        x = x.strip().upper()
        if x:
            out.add(x[:-4] if x.endswith("USDT") and len(x) > 4 else x)
    return out


def excluded_bases(cfg):
    return EXCLUDED_BASES | NON_CRYPTO_BASES | user_excludes(cfg)


def category_map(client):
    """base symbol -> category (lowercase) from Coinalyze /assets. Failure is non-fatal."""
    try:
        data = client.get("/assets")
    except ApiError as e:
        if e.status in (401, 403):
            raise
        log(f"  (asset categories unavailable: {e})")
        return {}
    out = {}
    for a in data if isinstance(data, list) else []:
        try:
            out[str(a["symbol"]).upper()] = str(a.get("asset_category") or "").lower()
        except (KeyError, TypeError, AttributeError):
            continue
    return out


SPOT_PREF = ("binance", "bybit", "okx", "coinbase", "kraken", "kucoin", "bitget", "gate")


def spot_symbol_map(client, exchanges):
    """base -> Coinalyze spot symbol that has buy/sell volume (Binance first). Failure is non-fatal (spot CVD just shows n/a)."""
    try:
        sm = client.get("/spot-markets")
    except ApiError as e:
        if e.status in (401, 403):
            raise
        log(f"  (spot markets unavailable: {e})")
        return {}
    names = {str(e.get("code")): str(e.get("name", "")).lower() for e in exchanges or []}

    def ex_rank(code):
        n = names.get(str(code), "")
        return next((i for i, p in enumerate(SPOT_PREF) if n == p or n.startswith(p)), len(SPOT_PREF))

    q_rank = {"USDT": 0, "USD": 1, "USDC": 2}
    best = {}
    for m in sm if isinstance(sm, list) else []:
        q = str(m.get("quote_asset", "")).upper()
        if not m.get("has_buy_sell_data") or q not in q_rank or "symbol" not in m:
            continue
        base = str(m.get("base_asset", "")).upper()
        key = (ex_rank(m.get("exchange")), q_rank[q])
        if base not in best or key < best[base][0]:
            best[base] = (key, m["symbol"])
    return {b: v[1] for b, v in best.items()}


def build_universe(client, cfg, now, prev=None, quick=False):
    excl = excluded_bases(cfg)
    exchanges = client.get("/exchanges")
    code = find_exchange_code(exchanges, "bybit")
    if code is None:
        raise ApiError("could not find Bybit in Coinalyze /exchanges")
    mexc_code = find_exchange_code(exchanges, "mexc")
    spot_map = spot_symbol_map(client, exchanges)
    markets = client.get("/future-markets")
    if not isinstance(markets, list) or not markets:
        raise ApiError("empty /future-markets response")

    def is_usdt_perp(m):
        return bool(m.get("is_perpetual")) and str(m.get("quote_asset", "")).upper() == "USDT"

    mexc_bases = {str(m.get("base_asset", "")).upper() for m in markets
                  if mexc_code is not None and str(m.get("exchange")) == mexc_code and is_usdt_perp(m)}
    cands, excluded_report, btc_symbol = [], set(), None
    for m in markets:
        if str(m.get("exchange")) != code and str(m.get("exchange", "")).lower() != "bybit":
            continue
        if not is_usdt_perp(m):
            continue
        base = str(m.get("base_asset", "")).upper()
        if base == "BTC" and btc_symbol is None:
            btc_symbol = m["symbol"]
        if base in excl:
            if base not in EXCLUDED_BASES:
                excluded_report.add(base)
            continue
        if not m.get("has_ohlcv_data", True) or not m.get("has_buy_sell_data", True):
            continue
        cands.append(m)

    if not quick:
        cats = category_map(client)
        if cats:
            tally = Counter(cats.get(str(m.get("base_asset", "")).upper(), "?") for m in cands)
            log("  asset categories among candidates: " + ", ".join(f"{k or 'none'}={v}" for k, v in tally.most_common(12)))
            flagged = [m for m in cands if any(w in cats.get(str(m.get("base_asset", "")).upper(), "") for w in NON_CRYPTO_CATEGORY_WORDS)]
            if len(flagged) <= 0.35 * len(cands):
                fs = {m["symbol"] for m in flagged}
                excluded_report.update(str(m.get("base_asset", "")).upper() for m in flagged)
                cands = [m for m in cands if m["symbol"] not in fs]
            else:
                log(f"  WARNING: category filter would remove {len(flagged)}/{len(cands)} coins - ignoring it (names list still applies)")
    elif prev and prev.get("pool"):
        pool_syms = {p["symbol"] for p in prev["pool"]}
        cands = [m for m in cands if m["symbol"] in pool_syms]
    log(f"Bybit exchange code {code}: {len(cands)} crypto USDT perps to rank (BTC symbol: {btc_symbol}); "
        f"non-crypto skipped: {', '.join(sorted(excluded_report)) or 'none'}")
    if not cands:
        raise ApiError("no Bybit USDT perpetuals found - Coinalyze response format may have changed")

    by_sym = {m["symbol"]: m for m in cands}
    syms = list(by_sym)
    ranked = []
    for i in range(0, len(syms), 18):  # 2 x 18 = 36 = the limiter budget; 20-symbol chunks wasted ~45% of every minute
        chunk = syms[i:i + 18]
        try:
            data = client.get("/open-interest", {"symbols": ",".join(chunk), "convert_to_usd": "true"}, cost=len(chunk))
        except ApiError as e:
            if e.status in (401, 403):
                raise
            log(f"  OI snapshot failed for a batch of {len(chunk)}: {e}")
            continue
        for item in data if isinstance(data, list) else []:
            try:
                ranked.append((float(item["value"]), item["symbol"]))
            except (KeyError, TypeError, ValueError):
                continue
    ranked = [r for r in ranked if r[0] >= cfg["min_universe_oi"] and r[1] in by_sym]
    ranked.sort(reverse=True)

    def mk(v, s_):
        m = by_sym[s_]
        base = str(m.get("base_asset") or "")
        return {"symbol": s_, "base": base, "denom": m.get("oi_lq_vol_denominated_in"),
                "ticker": m.get("symbol_on_exchange") or f"{base}USDT",
                "has_ls": bool(m.get("has_long_short_ratio_data", False)), "oi_usd": v,
                "mexc": (base.upper() in mexc_bases) if mexc_bases else None, "spot": spot_map.get(base.upper())}

    pool = [mk(v, s_) for v, s_ in ranked[: cfg["pool_size"]]]
    log(f"spot market mapped for {sum(1 for p in pool if p.get('spot'))}/{len(pool)} pool coins")
    chosen = pool[: cfg["universe_size"]]
    if len(chosen) < 10:
        raise ApiError(f"only {len(chosen)} coins passed the open-interest filter - refusing to overwrite universe")
    return {
        "generated": now.isoformat(),
        "full_generated": (prev or {}).get("full_generated") or (prev or {}).get("generated") if quick else now.isoformat(),
        "mode": "quick" if quick else "full", "exchange_code": code,
        "btc_symbol": btc_symbol or (prev or {}).get("btc_symbol"),
        "excluded": sorted(excluded_report), "symbols": chosen, "pool": pool,
    }


# ----------------------------------------------------------------------------- scan pipeline
def pick_items(uni, cfg):
    """Coins to scan: highest-OI first from the saved pool, minus excluded tickers (so edits to exclude.txt apply at once)."""
    excl = excluded_bases(cfg)
    src = uni.get("pool") or uni.get("symbols") or []
    items = [u for u in src if str(u.get("base", "")).upper() not in excl]
    return items[: cfg["universe_size"]]


def liq_summary(hist, now):
    """Last-3h liquidations vs that coin's normal 3h level. Display only (never scored)."""
    d = hist_to_df(hist, ["l", "s"])
    if len(d) < 10:
        return None
    end = pd.Timestamp(now).floor("h") - pd.Timedelta(hours=1)
    d = d.reindex(pd.date_range(end=end, periods=336, freq="h")).fillna(0.0)  # missing hour = no liquidations
    r3 = (d["l"] + d["s"]).rolling(3).sum()
    base = float(r3.iloc[:-1].median())
    cur = float(r3.iloc[-1])
    ratio = cur / base if base > 0 else (99.0 if cur > 0 else 0.0)
    return {"l3": float(d["l"].tail(3).sum()), "s3": float(d["s"].tail(3).sum()), "ratio": float(min(ratio, 99.0))}


def run_scan(cfg, client, uni, now):
    items = pick_items(uni, cfg)
    if len(items) < 5:
        raise FatalError("fewer than 5 usable coins in the coin list - run the 'universe' workflow")
    syms = [u["symbol"] for u in items]
    t_to = int(now.timestamp())
    t_from = t_to - cfg["lookback_days"] * 86400
    skipped = {}

    # Stage A: OI history for everyone (cheap build-up filter)
    oi_hist, errs = client.fetch_history("/open-interest-history", syms, "1hour", t_from, t_to, {"convert_to_usd": "false"})
    for s_, e in errs.items():
        skipped[s_] = f"OI fetch failed: {e}"
    prelim = {}
    for s_ in syms:
        if s_ in oi_hist:
            try:
                prelim[s_] = prelim_oi_score(oi_hist[s_])[0]
            except Skip as e:
                skipped[s_] = str(e)
        elif s_ not in skipped:
            skipped[s_] = "missing from response"
    if len(prelim) < max(5, 0.5 * len(syms)):
        raise FatalError(f"only {len(prelim)}/{len(syms)} coins returned usable OI data - Coinalyze problem or format change")

    top = sorted(prelim, key=prelim.get, reverse=True)[: cfg["stage_b_n"]]
    meta = {u["symbol"]: u for u in items}

    # Stage B: full data for the shortlist (+ BTC for the regime check)
    want_px = list(top) + ([uni["btc_symbol"]] if uni.get("btc_symbol") else [])
    px_hist, e1 = client.fetch_history("/ohlcv-history", want_px, "1hour", t_from, t_to)
    fr_hist, e2 = client.fetch_history("/funding-rate-history", top, "1hour", t_from, t_to)
    ls_syms = [s_ for s_ in top if meta[s_].get("has_ls")]
    ls_hist, e3 = client.fetch_history("/long-short-ratio-history", ls_syms, "1hour", t_from, t_to) if ls_syms else ({}, {})
    liq_hist = {}
    if cfg.get("liq"):
        liq_hist, _ = client.fetch_history("/liquidation-history", top, "1hour", t_from, t_to, {"convert_to_usd": "true"})
    spot_syms = [meta[s_]["spot"] for s_ in top if meta[s_].get("spot")]
    spot_hist = client.fetch_history("/ohlcv-history", spot_syms, "1hour", t_from, t_to)[0] if spot_syms else {}
    for s_, e in {**e3, **e2, **e1}.items():
        skipped.setdefault(s_, f"fetch failed: {e}")

    btc = {"ok": False, "text": "BTC regime unknown (no BTC data)"}
    if uni.get("btc_symbol") and uni["btc_symbol"] in px_hist:
        try:
            bdf = build_frame(px_hist[uni["btc_symbol"]], None, None, None, now, max_stale_h=cfg["max_stale_h"])
            btc = btc_regime(bdf)
        except Skip:
            pass

    ranked = []
    for s_ in top:
        if s_ not in px_hist:
            skipped.setdefault(s_, "no OHLCV returned")
            continue
        try:
            df = build_frame(px_hist[s_], oi_hist.get(s_), fr_hist.get(s_), ls_hist.get(s_), now,
                             denom=meta[s_].get("denom"), max_stale_h=cfg["max_stale_h"],
                             spot_hist=spot_hist.get(meta[s_].get("spot")) if meta[s_].get("spot") else None)
            res = score_coin(df, cfg)
            try:
                liq = liq_summary(liq_hist.get(s_), now) if liq_hist.get(s_) else None
            except Exception:
                liq = None
            res.update({"symbol": s_, "base": meta[s_].get("base") or s_, "ticker": meta[s_].get("ticker") or s_,
                        "mexc": meta[s_].get("mexc"), "liq": liq, "prelim": prelim[s_]})
            ranked.append(res)
        except Skip as e:
            skipped[s_] = str(e)
        except Exception as e:  # one coin must never kill the scan
            skipped[s_] = f"unexpected {type(e).__name__}: {e}"
    if not ranked:
        raise FatalError("no coins could be scored (all skipped) - see skip reasons in the log")
    ranked.sort(key=lambda r: (TIER_RANK[r["tier"]], -r["score"]))
    n_imm = 0
    for r in ranked:  # never more than MAX_IMMINENT per scan: the rest drop to BUILDING
        if r["tier"] == "IMMINENT":
            n_imm += 1
            if n_imm > cfg["max_imminent"]:
                r["tier"] = "BUILDING"
    ranked.sort(key=lambda r: (TIER_RANK[r["tier"]], -r["score"]))
    return {
        "ranked": ranked, "btc": btc, "skipped": skipped,
        "stats": {"universe": len(syms), "stageA_ok": len(prelim), "stageB": len(top), "scored": len(ranked),
                  "api_calls": client.calls},
    }


# ----------------------------------------------------------------------------- messages
def sydney(ts):
    try:
        from zoneinfo import ZoneInfo
        return ts.astimezone(ZoneInfo("Australia/Sydney"))
    except Exception:
        return ts.astimezone(dt.timezone(dt.timedelta(hours=11)))


def _f(x, spec="+.1f", na="n/a"):
    return na if x is None or (isinstance(x, float) and math.isnan(x)) else format(x, spec)


def funding_minutes_left(now):
    return int(((8 - now.hour % 8) * 60 - now.minute) % (8 * 60))


def fmt_px(x):
    if x is None or not math.isfinite(x):
        return "n/a"
    ax = abs(x)
    if ax >= 1000:
        return f"{x:,.1f}"
    if ax >= 100:
        return f"{x:.2f}"
    if ax >= 1:
        return f"{x:.3f}"
    if ax >= 0.01:
        return f"{x:.4f}"
    return f"{x:.6f}"


def fmt_usd(x):
    ax = abs(x)
    if ax >= 1e9:
        return f"${x / 1e9:.1f}B"
    if ax >= 1e6:
        return f"${x / 1e6:.1f}M"
    if ax >= 1e3:
        return f"${x / 1e3:.0f}K"
    return f"${x:.0f}"


def fmt_coin(i, c):
    m = c["m"]
    icon = {"IMMINENT": "⚡", "BUILDING": "\U0001f3d7", "WATCH": "\U0001f440"}[c["tier"]]
    esc = html.escape
    mexc = c.get("mexc")
    div = " \u00b7 price-CVD DIVERGENCE" if m["cvd_div"] else ""
    tag = " · MEXC✓" if mexc is True else (" · not on MEXC" if mexc is False else "")
    lines = [
        f"{i}. <b>{esc(str(c.get('ticker') or c['symbol']))}</b> {icon} {c['tier']} · score {c['score']:.0f}{tag}",
        f"   {esc(c['lean'])}",
        f"   OI {_f(m['oi4_chg'] * 100)}% 4h / {_f(m['oi1d_chg'] * 100)}% 24h (z {_f(m['oi4_z'])}) · price {_f(m['ret24'] * 100)}% 24h",
        f"   CVD 4h z: futures {_f(m['imb4_z'])} / spot {_f(m.get('spot_imb4_z', float('nan')))}{div}",
        f"   Flow: {esc(c.get('cvd_mode', 'spot n/a'))} \u00b7 funding {_f(m['fund_last'], '+.4f')} (z {_f(m['fund_z'])})",
        f"   Squeeze: 4H range pctile {_f(m['bbw_pct'] * 100, '.0f')} (low = coiled) · 1h vol {m['vol_ratio']:.1f}x · 1h range {m['range_ratio']:.1f}x",
    ]
    lv = c.get("levels")
    if lv:
        lines.append(f"   Px {fmt_px(lv['px'])} · 24h {fmt_px(lv['lo24'])}–{fmt_px(lv['hi24'])} · 3d {fmt_px(lv['lo3d'])}–{fmt_px(lv['hi3d'])}")
    lq = c.get("liq")
    if lq and lq["ratio"] >= 2.0 and lq["l3"] + lq["s3"] >= 50000:
        lines.append(f"   Liquidations 3h: long {fmt_usd(lq['l3'])} / short {fmt_usd(lq['s3'])} ({lq['ratio']:.1f}x normal)")
    if c["flags"]:
        lines.append("   ⚠ " + esc(", ".join(c["flags"])))
    return "\n".join(lines)


def format_message(kind, ranked, btc, now, top_k, notes=None, new_imminent=None):
    head = {"alert": "⚡ <b>IMMINENT ALERT</b>", "digest": "\U0001f553 <b>4H DIGEST</b>", "heartbeat": "✅ <b>Scanner alive</b>"}[kind]
    s = sydney(now)
    out = [f"{head} — {s:%a %d %b %H:%M} Sydney · v2", html.escape(btc["text"])]
    mins = funding_minutes_left(now)
    if mins <= 90:
        out.append(f"⏱ Funding settles in {mins} min - positioning can shift around it")
    if new_imminent:
        names = {c["symbol"]: (c.get("ticker") or c["symbol"]) for c in ranked}
        out.append("New: " + ", ".join(html.escape(names.get(x, x)) for x in new_imminent))
    out.append("")
    for i, c in enumerate(ranked[:top_k], 1):
        out.append(fmt_coin(i, c))
        out.append("")
    out.append("<i>Shortlist only, not a trade signal.</i>")
    for n in notes or []:
        out.append(html.escape(n))
    return "\n".join(out)


def split_message(text, limit=3800):
    if len(text) <= limit:
        return [text]
    parts, cur = [], ""
    for block in text.split("\n\n"):
        if len(cur) + len(block) + 2 > limit and cur:
            parts.append(cur)
            cur = ""
        while len(block) > limit:  # pathological single block
            parts.append(block[:limit])
            block = block[limit:]
        cur = f"{cur}\n\n{block}" if cur else block
    if cur:
        parts.append(cur)
    return parts


def tg_send(token, chat_id, text, session=None, sleep=time.sleep):
    if not token or not chat_id:
        raise TelegramError("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is empty")
    s = session or requests
    for chunk in split_message(text):
        for attempt in range(2):
            try:
                r = s.post(f"{TG_URL}/bot{token}/sendMessage", timeout=20, json={
                    "chat_id": str(chat_id).strip(), "text": chunk, "parse_mode": "HTML", "disable_web_page_preview": True})
            except requests.RequestException as e:
                raise TelegramError(f"network error talking to Telegram: {type(e).__name__}")  # no URL => token never leaks
            try:
                j = r.json()
            except ValueError:
                raise TelegramError(f"Telegram returned non-JSON (HTTP {r.status_code})")
            if j.get("ok"):
                break
            if r.status_code == 429 and attempt == 0:
                sleep(float((j.get("parameters") or {}).get("retry_after", 5)) + 1)
                continue
            raise TelegramError(f"{j.get('error_code', r.status_code)}: {j.get('description')}")


# ----------------------------------------------------------------------------- state / alert logic
def load_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, ValueError):
        return default


def save_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1))
    tmp.replace(p)


def _hours_since(iso, now):
    try:
        return (now - dt.datetime.fromisoformat(iso)).total_seconds() / 3600
    except (TypeError, ValueError):
        return 1e9


def decide_send(top, state, now, cfg, force=False):
    """Returns (kind, new_imminent) or (None, [])."""
    prev_top = set(state.get("last_top", []))
    prev_tier = state.get("last_tiers", {})
    new_imm = []
    for c in top:
        if c["tier"] != "IMMINENT":
            continue
        if prev_tier.get(c["symbol"]) == "IMMINENT" and c["symbol"] in prev_top:
            continue
        if _hours_since(state.get("last_alert", {}).get(c["symbol"]), now) < cfg["cooldown_h"]:
            continue
        new_imm.append(c["symbol"])
    digest_due = now.hour % 4 == 0 and state.get("last_digest_key") != f"{now:%Y-%m-%dT%H}"
    if force:
        return "digest", new_imm
    if digest_due:
        return "digest", new_imm
    if new_imm:
        return "alert", new_imm
    if _hours_since(state.get("last_heartbeat"), now) >= 24:
        return "heartbeat", []
    return None, []


LOG_FIELDS = ["ts_utc", "symbol", "tier", "score", "setup", "trigger", "oi4_z", "oi1d_z", "oi2h_z", "fund_z", "lsr_z",
              "imb4_z", "bbw_pct", "ret4", "ret24", "vol_ratio", "price", "liq_ratio", "mexc", "spot_imb4_z", "cvd_mode", "flags"]


def append_log(path, ranked, now):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    header = ",".join(LOG_FIELDS)
    if p.exists():
        try:
            first = p.read_text().splitlines()[0]
        except (IndexError, OSError):
            first = ""
        if first != header:  # older format: keep it, start a fresh file
            p.replace(p.with_name(p.stem + "_old" + p.suffix))
    new = not p.exists()
    with p.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(LOG_FIELDS)
        for c in ranked:
            m = c["m"]
            lq = c.get("liq") or {}
            w.writerow([now.isoformat(timespec="minutes"), c["symbol"], c["tier"], f"{c['score']:.1f}", f"{c['setup']:.3f}",
                        f"{c['trigger']:.3f}", *[("" if math.isnan(m[k]) else f"{m[k]:.3f}") for k in
                                                 ("oi4_z", "oi1d_z", "oi2h_z", "fund_z", "lsr_z", "imb4_z", "bbw_pct")],
                        f"{m['ret4']:.4f}", f"{m['ret24']:.4f}", f"{m['vol_ratio']:.2f}",
                        f"{c['p0']:.8g}" if c.get("p0") else "", f"{lq['ratio']:.2f}" if lq else "",
                        {True: "1", False: "0", None: ""}[c.get("mexc")],
                        "" if math.isnan(m.get("spot_imb4_z", float("nan"))) else f"{m['spot_imb4_z']:.3f}",
                        c.get("cvd_mode", ""), "|".join(c["flags"])])


# ----------------------------------------------------------------------------- outcome tracker
OUT_CHECKS = (4, 12, 24)  # hours after the alert at which we look back at what price did


def _num(x):
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def load_outcomes(path):
    d = load_json(path, {})
    return {"open": list(d.get("open", [])), "finished": list(d.get("finished", []))}


def track_new(out, ranked_top, now, digest=False, cooldown_h=12.0, cap_imm=3, cap_bld=2):
    """Remember new IMMINENT coins (and, at digests, the top BUILDING ones) so we can check later what price did."""
    recent = {}
    for e in out["open"] + out["finished"]:
        recent[e["symbol"]] = min(recent.get(e["symbol"], 1e9), _hours_since(e.get("added"), now))
    n_i = n_b = 0
    added = []
    for c in ranked_top:
        if c["tier"] == "IMMINENT":
            if n_i >= cap_imm:
                continue
        elif c["tier"] == "BUILDING" and digest:
            if n_b >= cap_bld:
                continue
        else:
            continue
        if recent.get(c["symbol"], 1e9) < cooldown_h or not c.get("p0") or not c.get("t0"):
            continue
        out["open"].append({
            "symbol": c["symbol"], "ticker": c.get("ticker") or c["symbol"], "tier": c["tier"],
            "score": round(c["score"], 1), "lean": c["lean"], "added": now.isoformat(), "t0": c["t0"], "p0": c["p0"],
            "typ4": _num(c["m"].get("typ4")), "p90_12": _num(c["m"].get("exc12_p90")), "done": {}})
        recent[c["symbol"]] = 0.0
        if c["tier"] == "IMMINENT":
            n_i += 1
        else:
            n_b += 1
        added.append(c["symbol"])
    return added


def evaluate_outcomes(client, out, now):
    """For alerts that reached 4h/12h/24h: fetch hourly candles, record max up / max down / close vs the alert price."""
    now_ts = pd.Timestamp(now)
    due = {}
    for e in out["open"]:
        t0 = pd.Timestamp(e["t0"])
        if any(str(n) not in e["done"] and now_ts >= t0 + pd.Timedelta(hours=n, minutes=5) for n in OUT_CHECKS):
            due.setdefault(e["symbol"], []).append(t0)
    hist = {}
    if due:
        t_from = int(min(t for ts in due.values() for t in ts).timestamp()) - 3600
        hist, _ = client.fetch_history("/ohlcv-history", list(due), "1hour", t_from, int(now.timestamp()))
    finished = []
    for e in list(out["open"]):
        t0 = pd.Timestamp(e["t0"])
        bars = hist_to_df(hist.get(e["symbol"]), ["o", "h", "l", "c", "v", "bv"]) if hist.get(e["symbol"]) else None
        for n in OUT_CHECKS:
            k = str(n)
            end = t0 + pd.Timedelta(hours=n)
            if k in e["done"] or now_ts < end + pd.Timedelta(minutes=5):
                continue
            r = None
            if bars is not None and len(bars) and e.get("p0"):
                sel = bars[(bars.index >= t0) & (bars.index + pd.Timedelta(hours=1) <= end)]
                if len(sel) >= n - 1:
                    r = {"up": _num(sel["h"].max() / e["p0"] - 1), "down": _num(sel["l"].min() / e["p0"] - 1),
                         "close": _num(sel["c"].iloc[-1] / e["p0"] - 1)}
            if r is None and now_ts > end + pd.Timedelta(hours=6):
                r = {"up": None, "down": None, "close": None}  # data never arrived: stop waiting
            if r is not None:
                e["done"][k] = r
        if all(str(n) in e["done"] for n in OUT_CHECKS):
            out["open"].remove(e)
            out["finished"].append(e)
            finished.append(e)
    out["finished"] = out["finished"][-300:]
    return finished


def _pc(x):
    return "n/a" if x is None else f"{x * 100:+.1f}%"


def big_move(e):
    """True/False: did the 12h move beat 90% of this coin's normal 12h moves? None if unknown."""
    r = (e.get("done") or {}).get("12")
    if not r or r.get("up") is None or r.get("down") is None or not e.get("p90_12"):
        return None
    return max(r["up"], -r["down"]) >= e["p90_12"]


def outcome_report(newly, out, now):
    esc = html.escape
    lines = ["\U0001f4ca <b>OUTCOME REPORT</b> — how past alerts played out", "<i>(max up / max down vs the price at the alert)</i>", ""]
    for e in newly[:8]:
        parts = []
        for n in OUT_CHECKS:
            r = e["done"].get(str(n)) or {}
            parts.append(f"{n}h {_pc(r.get('up'))}/{_pc(r.get('down'))}" if r.get("up") is not None else f"{n}h n/a")
        bm = big_move(e)
        verdict = "" if bm is None else (" ✅ big move" if bm else " — normal range")
        when = sydney(pd.Timestamp(e["t0"]).to_pydatetime())
        lines.append(f"{esc(str(e['ticker']))} {e['tier']} (score {e['score']:.0f}) {when:%a %H:%M}: " + " · ".join(parts) + verdict)
    lines.append("")
    for tier in ("IMMINENT", "BUILDING"):
        rows = [e for e in out["finished"] if e["tier"] == tier and big_move(e) is not None]
        if rows:
            hits = sum(1 for e in rows if big_move(e))
            lines.append(f"Scorecard {tier}: {hits}/{len(rows)} had a 12h move bigger than 90% of that coin's normal ones "
                         f"({100 * hits / len(rows):.0f}%; pure chance would be about 10%)")
    lines.append("<i>Small samples: judge after 30+ alerts.</i>")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- backtest
def backtest_samples(df, cfg, step_h=3):
    """Replays the scorer every step_h hours over one coin's history (only data up to that hour is visible to it) and
    records how big the move over the NEXT 4h and 12h was."""
    rows = []
    hi, lo, cl, idx = df["h"].values, df["l"].values, df["c"].values, df.index
    for i in range(cfg["min_bars"] + 10, len(df) - 12, max(1, step_h)):
        try:
            r = score_coin(df.iloc[: i + 1], cfg)
        except Skip:
            continue
        except Exception:
            continue
        p = cl[i]
        if not p or not math.isfinite(p):
            continue
        e12 = max(hi[i + 1:i + 13].max() / p - 1, 1 - lo[i + 1:i + 13].min() / p)
        e4 = max(hi[i + 1:i + 5].max() / p - 1, 1 - lo[i + 1:i + 5].min() / p)
        rows.append({"t": idx[i].isoformat(), "tier": r["tier"], "score": r["score"], "cvd_mode": r["cvd_mode"],
                     "e4": float(e4), "e12": float(e12), "p90_4": r["m"].get("exc4_p90"), "p90_12": r["m"].get("exc12_p90")})
    return rows


def backtest_summary(rows):
    """Hit = the following move was bigger than 90% of that coin's own normal moves, so pure chance is about 10%."""
    d = pd.DataFrame(rows)
    if d.empty:
        return {"n": 0, "groups": {}}
    d = d.dropna(subset=["p90_4", "p90_12"])
    d["hit4"] = d["e4"] >= d["p90_4"]
    d["hit12"] = d["e12"] >= d["p90_12"]

    def grp(x):
        return {"n": int(len(x)), "hit4": float(x["hit4"].mean()) if len(x) else None,
                "hit12": float(x["hit12"].mean()) if len(x) else None}

    groups = {"ALL samples": grp(d)}
    for tier in ("IMMINENT", "BUILDING", "WATCH"):
        groups[tier] = grp(d[d["tier"] == tier])
    if len(d) >= 20:
        groups["score top 5%"] = grp(d[d["score"] >= d["score"].quantile(0.95)])
    act = d[d["tier"].isin(["IMMINENT", "BUILDING"])]
    for mode, x in act.groupby("cvd_mode"):
        if len(x) >= 10:
            groups[f"setup + {mode}"] = grp(x)
    return {"n": int(len(d)), "groups": groups}


def backtest_text(summ, days, n_coins):
    esc = html.escape
    lines = [f"\U0001f9ea <b>BACKTEST</b> — {n_coins} coins, ~{days} days of hourly history, {summ['n']} samples",
             "Hit = next-move bigger than 90% of that coin's normal moves (chance = 10%).", "<pre>"]
    lines.append(f"{'group':<34}{'n':>6}{'in 4h':>8}{'in 12h':>8}")
    for name, g in summ["groups"].items():
        if g["n"] == 0:
            continue
        lines.append(f"{esc(name[:33]):<34}{g['n']:>6}{g['hit4'] * 100:>7.0f}%{g['hit12'] * 100:>7.0f}%")
    lines.append("</pre>")
    lines.append("<i>Samples overlap (3h steps, 12h windows), so treat small groups loosely. Direction is not measured, only "
                 "size. The weights were not tuned on this data, but past hit rates do not guarantee future ones.</i>")
    return "\n".join(lines)


def cmd_backtest(cfg, client, token, chat):
    now = dt.datetime.now(UTC).replace(second=0, microsecond=0)
    uni = load_json(cfg["data_dir"] / "universe.json", None)
    if not uni or not (uni.get("symbols") or uni.get("pool")):
        log("BACKTEST FAILED: data/universe.json is missing - run the 'universe' workflow first")
        return 1
    items = pick_items(uni, cfg)[: cfg["bt_coins"]]
    syms = [u["symbol"] for u in items]
    meta = {u["symbol"]: u for u in items}
    t_to = int(now.timestamp())
    t_from = t_to - 60 * 86400
    log(f"backtest: {len(syms)} coins, fetching history (about {len(syms) * 5 / cfg['calls_per_min']:.0f} min of API calls)")
    oi, _ = client.fetch_history("/open-interest-history", syms, "1hour", t_from, t_to, {"convert_to_usd": "false"})
    px, _ = client.fetch_history("/ohlcv-history", syms, "1hour", t_from, t_to)
    fr, _ = client.fetch_history("/funding-rate-history", syms, "1hour", t_from, t_to)
    lsyms = [s_ for s_ in syms if meta[s_].get("has_ls")]
    ls = client.fetch_history("/long-short-ratio-history", lsyms, "1hour", t_from, t_to)[0] if lsyms else {}
    ssyms = [meta[s_]["spot"] for s_ in syms if meta[s_].get("spot")]
    sp = client.fetch_history("/ohlcv-history", ssyms, "1hour", t_from, t_to)[0] if ssyms else {}
    rows, used = [], 0
    for k, s_ in enumerate(syms, 1):
        if s_ not in px:
            continue
        try:
            df = build_frame(px[s_], oi.get(s_), fr.get(s_), ls.get(s_), now, denom=meta[s_].get("denom"),
                             max_stale_h=cfg["max_stale_h"], spot_hist=sp.get(meta[s_].get("spot")) if meta[s_].get("spot") else None)
        except Skip as e:
            log(f"  skip {s_}: {e}")
            continue
        r = backtest_samples(df, cfg, cfg["bt_step_h"])
        rows += r
        used += 1
        log(f"  [{k}/{len(syms)}] {s_}: {len(df)}h of data, {len(r)} samples")
    summ = backtest_summary(rows)
    text = backtest_text(summ, 45, used)
    log(re.sub(r"<[^>]+>", "", html.unescape(text)))
    save_json(cfg["data_dir"] / "backtest_summary.json", {"generated": now.isoformat(), "coins": used, **summ})
    if token and chat:
        try:
            tg_send(token, chat, text)
        except TelegramError as e:
            log(f"(backtest summary not sent: {e})")
    return 0 if summ["n"] else 1


# ----------------------------------------------------------------------------- commands
def universe_summary(uni):
    names = ", ".join(str(u["base"]) for u in uni["symbols"])
    ex = ", ".join(uni.get("excluded") or []) or "none"
    return (f"\U0001f504 <b>Coin list rebuilt (full)</b>\n{len(uni['symbols'])} coins in the scan list "
            f"(pool of {len(uni.get('pool', []))}).\nNon-crypto contracts skipped: {html.escape(ex)}\n\n"
            f"{html.escape(names)}\n\n<i>See a non-crypto name here? Add its ticker to data/exclude.txt on GitHub.</i>")


def cmd_universe(cfg, client, mode, token="", chat=""):
    now = dt.datetime.now(UTC)
    path = cfg["data_dir"] / "universe.json"
    prev = load_json(path, None)
    has_pool = bool(prev and prev.get("pool"))
    if mode == "universe-quick":
        quick = has_pool
    elif mode == "universe-auto":
        quick = has_pool and _hours_since(prev.get("full_generated"), now) < cfg["full_every_h"]
    else:
        quick = False
    log(f"coin list refresh mode: {'QUICK (re-rank saved pool)' if quick else 'FULL'}")
    uni = build_universe(client, cfg, now, prev, quick)
    save_json(path, uni)
    log(f"universe.json saved: {len(uni['symbols'])} coins (pool {len(uni['pool'])}), top 10: "
        + ", ".join(u["base"] for u in uni["symbols"][:10]))
    log("full scan list: " + ", ".join(u["base"] for u in uni["symbols"]))
    if not quick and token and chat:
        try:
            tg_send(token, chat, universe_summary(uni))
        except TelegramError as e:
            log(f"(coin list summary not sent: {e})")
    return 0


def notify_failure(cfg, token, chat, state, msg):
    now = dt.datetime.now(UTC)
    if _hours_since(state.get("last_failure_alert"), now) < 6:
        return
    try:
        tg_send(token, chat, "⚠️ <b>Scanner problem</b>\n" + html.escape(msg[:900]))
        state["last_failure_alert"] = now.isoformat()
    except TelegramError as e:
        log(f"(could not send failure notice to Telegram: {e})")


def cmd_scan(cfg, client, token, chat, dry):
    now = dt.datetime.now(UTC).replace(second=0, microsecond=0)
    sp = cfg["data_dir"] / "state.json"
    op = cfg["data_dir"] / "outcomes.json"
    state = load_json(sp, {})
    try:
        uni = load_json(cfg["data_dir"] / "universe.json", None)
        if not uni or not (uni.get("symbols") or uni.get("pool")):
            raise FatalError("data/universe.json is missing - run the 'universe' workflow once first")
        res = run_scan(cfg, client, uni, now)
    except (ApiError, FatalError) as e:
        log(f"SCAN FAILED: {e}")
        if not dry:
            notify_failure(cfg, token, chat, state, f"Scan failed: {e}")
            save_json(sp, state)
        return 1

    ranked, btc, stats = res["ranked"], res["btc"], res["stats"]
    top = ranked[: cfg["top_k"]]
    log(f"v{SCANNER_VERSION} stats: {stats}")
    for s_, why in sorted(res["skipped"].items()):
        log(f"  skipped {s_}: {why}")
    for c in top:
        log(f"  {c['tier']:<8} {c['score']:5.1f} setup {c['setup']:.2f} trig {c['trigger']:.2f}  {c['symbol']}")

    notes = []
    age_h = _hours_since(uni.get("generated"), now)
    if age_h > 72:
        notes.append(f"Note: coin list is {age_h / 24:.0f} days old - check the daily universe workflow.")
    if len(res["skipped"]) > 0.4 * stats["universe"]:
        notes.append(f"Note: {len(res['skipped'])}/{stats['universe']} coins skipped (data gaps).")

    kind, new_imm = decide_send(top, state, now, cfg)
    if dry:
        log("---- DRY RUN message (not sent) ----")
        log(re.sub(r"<[^>]+>", "", html.unescape(format_message(kind or "digest", ranked, btc, now, cfg["top_k"], notes, new_imm))))
        log(f"outcome tracker: {len(load_outcomes(op)['open'])} alert(s) currently being tracked")
        return 0

    append_log(cfg["data_dir"] / "scan_log.csv", ranked, now)
    if kind:
        try:
            tg_send(token, chat, format_message(kind, ranked, btc, now, cfg["top_k"], notes, new_imm))
            log(f"sent Telegram {kind}")
            state["last_heartbeat"] = now.isoformat()
            if kind == "digest":
                state["last_digest_key"] = f"{now:%Y-%m-%dT%H}"
            if kind in ("digest", "alert"):
                la = state.setdefault("last_alert", {})
                for c in top:
                    if c["tier"] == "IMMINENT":
                        la[c["symbol"]] = now.isoformat()
        except TelegramError as e:
            log(f"TELEGRAM FAILED: {e}")
            save_json(sp, {**state, "last_top": [c["symbol"] for c in top]})
            return 1
    else:
        log("nothing new to send this run")
    state["last_top"] = [c["symbol"] for c in top]
    state["last_tiers"] = {c["symbol"]: c["tier"] for c in top}
    state["last_scan"] = now.isoformat()
    save_json(sp, state)

    # outcome tracker: never allowed to break a scan
    try:
        outcomes = load_outcomes(op)
        newly = evaluate_outcomes(client, outcomes, now)
        added = track_new(outcomes, top, now, digest=(kind == "digest"))
        save_json(op, outcomes)
        if added:
            log(f"tracking {len(added)} new alert(s): {', '.join(added)}")
        if newly:
            try:
                tg_send(token, chat, outcome_report(newly, outcomes, now))
                log(f"sent outcome report for {len(newly)} alert(s)")
            except TelegramError as e:
                log(f"(outcome report not sent: {e})")
    except Exception as e:
        log(f"(outcome tracker problem, ignored: {type(e).__name__}: {e})")
    return 0


def diagnose(cfg):
    ok_all = True
    log(f"scanner version {SCANNER_VERSION}")
    token, chat, key = (os.environ.get(k, "") for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "COINALYZE_API_KEY"))
    log("== 1. Secrets present? (names only, values never printed)")
    for name, val in (("TELEGRAM_BOT_TOKEN", token), ("TELEGRAM_CHAT_ID", chat), ("COINALYZE_API_KEY", key)):
        good = bool(val.strip())
        ok_all &= good
        log(f"   {'PASS' if good else 'FAIL'}  {name} {'set' if good else 'EMPTY - add it under Settings > Secrets and variables > Actions'}")
    if token != token.strip() or chat != chat.strip() or key != key.strip():
        log("   WARN  a secret has leading/trailing spaces or a newline - re-paste it without extra spaces")

    log("== 2. Telegram")
    try:
        r = requests.get(f"{TG_URL}/bot{token.strip()}/getMe", timeout=20)
        j = r.json()
        if j.get("ok"):
            log(f"   PASS  token valid, bot username: @{j['result'].get('username')}")
            try:
                tg_send(token.strip(), chat.strip(), f"✅ Scanner diagnose v{SCANNER_VERSION}: Telegram test message")
                log("   PASS  test message delivered - check your Telegram")
            except TelegramError as e:
                ok_all = False
                hint = ""
                if "chat not found" in str(e).lower():
                    hint = " -> chat id is wrong, or you have not pressed START on the bot yet. Open your bot in Telegram, press Start, send 'hi', then get your id from @userinfobot"
                elif "forbidden" in str(e).lower():
                    hint = " -> the bot was blocked/removed. Unblock it (or add it to the group)"
                log(f"   FAIL  sendMessage: {e}{hint}")
        else:
            ok_all = False
            log(f"   FAIL  getMe: {j.get('error_code')} {j.get('description')} -> bot token is wrong (copy it again from @BotFather)")
    except (requests.RequestException, ValueError) as e:
        ok_all = False
        log(f"   FAIL  could not reach Telegram: {type(e).__name__}")

    log("== 3. Coinalyze")
    client = Coinalyze(key.strip(), limiter=RateLimiter(cfg["calls_per_min"]), batch=cfg["batch"])
    try:
        ex = client.get("/exchanges")
        code = find_exchange_code(ex, "bybit")
        log(f"   PASS  API key accepted, {len(ex)} exchanges, Bybit code = {code}, MEXC code = {find_exchange_code(ex, 'mexc')}")
        if code is None:
            raise ApiError("Bybit not in exchange list")
        mk = client.get("/future-markets")
        byb = [m for m in mk if str(m.get("exchange")) == code and m.get("is_perpetual") and str(m.get("quote_asset", "")).upper() == "USDT"]
        log(f"   PASS  {len(byb)} Bybit USDT perpetuals found")
        if not byb:
            raise ApiError("no Bybit USDT perps - format changed?")
        sample = next((m for m in byb if str(m.get("base_asset", "")).upper() == "SOL"), byb[0])["symbol"]
        t_to = int(time.time())
        for ep, flds in (("/open-interest-history", ("c",)), ("/ohlcv-history", ("c", "v", "bv")),
                         ("/funding-rate-history", ("c",)), ("/long-short-ratio-history", ("r",)),
                         ("/liquidation-history", ("l", "s"))):
            data, errs = client.fetch_history(ep, [sample], "1hour", t_to - 3 * 86400, t_to)
            h = data.get(sample, [])
            if not h:
                must = ep in ("/open-interest-history", "/ohlcv-history")
                log(f"   {'FAIL' if must else 'WARN'}  {ep}: no data for {sample} {errs.get(sample, '')}")
                ok_all &= not must
                continue
            missing = [f for f in flds if f not in h[-1]]
            age = (t_to - h[-1]["t"]) / 3600
            log(f"   {'PASS' if not missing else 'FAIL'}  {ep}: {len(h)} points, newest {age:.1f}h old, fields {sorted(h[-1])}"
                + (f" MISSING {missing}" if missing else ""))
            ok_all &= not missing
        smap = spot_symbol_map(client, ex)
        ssym = smap.get("SOL") or (next(iter(smap.values())) if smap else None)
        log(f"   spot markets mapped for {len(smap)} coins; sample {ssym}")
        if ssym:
            sd, serr = client.fetch_history("/ohlcv-history", [ssym], "1hour", t_to - 3 * 86400, t_to)
            sh = sd.get(ssym, [])
            if sh and "bv" in sh[-1] and "v" in sh[-1]:
                log(f"   PASS  spot candles with buy volume: {len(sh)} points, fields {sorted(sh[-1])}")
            else:
                log(f"   WARN  spot candles unusable for {ssym}: {serr.get(ssym, 'no bv field or no data')} (spot CVD will show n/a)")
        else:
            log("   WARN  no spot markets found (spot CVD will show n/a)")
        log("== 4. Asset categories (info only - helps the crypto-only filter)")
        cats = category_map(client)
        tally = Counter(cats.get(str(m.get("base_asset", "")).upper(), "?") for m in byb)
        log("   " + (", ".join(f"{k or 'none'}={v}" for k, v in tally.most_common(25)) or "no categories returned"))
        flagged = sorted({str(m.get("base_asset", "")).upper() for m in byb
                          if any(w in cats.get(str(m.get("base_asset", "")).upper(), "") for w in NON_CRYPTO_CATEGORY_WORDS)})
        log(f"   category filter would skip {len(flagged)}: {', '.join(flagged) or 'none'}")
    except ApiError as e:
        ok_all = False
        log(f"   FAIL  {e}")
    log("== RESULT: " + ("ALL GOOD" if ok_all else "something failed - read the FAIL lines above"))
    return 0 if ok_all else 1


def main(argv):
    mode = (argv[1] if len(argv) > 1 else "scan").strip().lower() or "scan"
    cfg = load_cfg()
    if mode == "diagnose":
        return diagnose(cfg)
    if mode not in ("scan", "scan-dry-run", "universe", "universe-auto", "universe-quick", "backtest"):
        log(f"unknown mode {mode!r}; use scan | scan-dry-run | universe-auto | universe | universe-quick | backtest | diagnose")
        return 2
    client = Coinalyze(os.environ.get("COINALYZE_API_KEY", "").strip(), limiter=RateLimiter(cfg["calls_per_min"]), batch=cfg["batch"])
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    try:
        if mode.startswith("universe"):
            return cmd_universe(cfg, client, mode, token, chat)
        if mode == "backtest":
            return cmd_backtest(cfg, client, token, chat)
        return cmd_scan(cfg, client, token, chat, dry=(mode == "scan-dry-run"))
    except ApiError as e:
        log(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
