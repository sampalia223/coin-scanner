#!/usr/bin/env python3
"""
Altcoin volatility scanner  (data: Coinalyze free API  ->  alerts: Telegram)

Modes (python scanner.py <mode>):
  universe       build/refresh data/universe.json (Bybit USDT perps ranked by open interest). Run daily.
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
from collections import deque
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

# scoring weights (sum to 1 inside each block). These are starting points, tune from data/scan_log.csv.
SETUP_W = {"oi4h": 0.25, "oi1d": 0.15, "compression": 0.15, "crowding": 0.15, "cvd": 0.15, "stealth": 0.15}
TRIGGER_W = {"oi_accel": 0.35, "vol_exp": 0.25, "cvd_1h": 0.20, "range_exp": 0.20}
SETUP_MIN_FOR_TIER = 0.50          # untuned starting point - adjust after a few weeks of data/scan_log.csv
TRIGGER_MIN_FOR_IMMINENT = 0.30
TIER_RANK = {"IMMINENT": 0, "BUILDING": 1, "WATCH": 2}


# ----------------------------------------------------------------------------- config / errors
def _e(name, default):
    v = os.environ.get(name)
    return default if v is None or str(v).strip() == "" else v


def load_cfg():
    return {
        "data_dir": Path(_e("SCANNER_DATA_DIR", "data")),
        "universe_size": int(_e("UNIVERSE_SIZE", "60")),
        "stage_b_n": int(_e("STAGE_B_N", "12")),
        "top_k": int(_e("TOP_K", "5")),
        "min_turnover": float(_e("MIN_TURNOVER_USD", "2000000")),
        "min_universe_oi": float(_e("MIN_UNIVERSE_OI_USD", "3000000")),
        "lookback_days": int(_e("LOOKBACK_DAYS", "30")),
        "min_bars": int(_e("MIN_BARS", "300")),
        "calls_per_min": int(_e("CALLS_PER_MIN", "36")),
        "cooldown_h": float(_e("COOLDOWN_HOURS", "4")),
        "max_stale_h": float(_e("MAX_STALE_HOURS", "2.5")),
        "batch": int(_e("BATCH_SIZE", "10")),
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


def rz(series, min_hist=20, cap=5.0):
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


def build_frame(px_hist, oi_hist, fr_hist, ls_hist, now, denom=None, max_stale_h=2.5):
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
    out = pd.DataFrame({
        "o": g["o"].first(), "h": g["h"].max(), "l": g["l"].min(), "c": g["c"].last(),
        "v": g["v"].sum(min_count=1), "bv": g["bv"].sum(min_count=1),
        "oi": g["oi"].last(), "n": g["c"].count(),
    })
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
    z4 = rz(h4["oi"].pct_change())
    z1 = rz(d1["oi"].pct_change(), min_hist=14)
    z2 = rz(d.pct_change(2))
    comp = [zpos(z4), zpos(z1), zpos(z2)]
    return 0.4 * comp[0] + 0.3 * comp[1] + 0.3 * comp[2], {"oi4_z": z4, "oi1d_z": z1, "oi2h_z": z2}


# ----------------------------------------------------------------------------- scoring
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
    oi4_z, oi1d_z = rz(oi4_chg), rz(oi1d_chg, min_hist=14)
    oi2h_chg = df["oi"].pct_change(2)
    oi2h_z = rz(oi2h_chg)

    vol4 = h4["v"].replace(0, np.nan)
    imb4 = ((2 * h4["bv"] - h4["v"]) / vol4)
    imb4_z = rz(imb4)
    v3 = df["v"].rolling(3).sum().replace(0, np.nan)
    imb3h = (2 * df["bv"].rolling(3).sum() - df["v"].rolling(3).sum()) / v3
    imb3_z = rz(imb3h)

    c4 = h4["c"]
    bbw = 4 * c4.rolling(20).std() / c4.rolling(20).mean()
    pc = c4.shift(1)
    tr4 = pd.concat([(h4["h"] - h4["l"]), (h4["h"] - pc).abs(), (h4["l"] - pc).abs()], axis=1).max(axis=1) / c4
    atr4 = tr4.rolling(14).mean()
    pr_bb, pr_atr = pct_rank(bbw), pct_rank(atr4)
    comp_parts = [1 - p for p in (pr_bb, pr_atr) if not math.isnan(p)]
    compression = float(np.mean(comp_parts)) if comp_parts else 0.0

    fund_z = rz(df["fund"]) if df["fund"].notna().sum() > 50 else float("nan")
    lsr_z = rz(df["lsr"]) if df["lsr"].notna().sum() > 50 else float("nan")
    crowd_parts = [zabs(z) for z in (fund_z, lsr_z) if not math.isnan(z)]
    crowding = float(np.mean(crowd_parts)) if crowd_parts else 0.0

    stealth = clip01(1 - abs(ret24) / 0.10)
    price_dir = 0 if abs(ret4) < 0.002 else int(np.sign(ret4))
    cvd_dir = 0 if math.isnan(imb4_z) else int(np.sign(imb4.iloc[-1]))
    cvd_div = bool(price_dir != 0 and cvd_dir != 0 and cvd_dir != price_dir and not math.isnan(imb4_z) and abs(imb4_z) >= 1.0)
    cvd_score = clip01(zabs(imb4_z) + (0.15 if cvd_div else 0.0))

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
        "cvd_1h": zabs(imb3_z), "range_exp": clip01((range_ratio - 1) / 2),
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
    elif setup >= SETUP_MIN_FOR_TIER and trigger >= TRIGGER_MIN_FOR_IMMINENT:
        tier = "IMMINENT"
    elif setup >= SETUP_MIN_FOR_TIER:
        tier = "BUILDING"
    else:
        tier = "WATCH"

    fund_last = float(df["fund"].dropna().iloc[-1]) if df["fund"].notna().any() else float("nan")
    return {
        "score": float(score), "setup": float(setup), "trigger": float(trigger), "tier": tier, "flags": flags,
        "lean": lean_text(fund_z, lsr_z, imb4_z),
        "m": {
            "oi4_chg": float(oi4_chg.iloc[-1]), "oi1d_chg": float(oi1d_chg.iloc[-1]),
            "oi4_z": oi4_z, "oi1d_z": oi1d_z, "oi2h_z": oi2h_z,
            "fund_last": fund_last, "fund_z": fund_z, "lsr_z": lsr_z,
            "imb4_z": imb4_z, "imb3_z": imb3_z, "cvd_div": cvd_div,
            "bbw_pct": pr_bb, "atr_pct": pr_atr, "ret4": ret4, "ret24": ret24,
            "vol_ratio": vol_ratio, "range_ratio": range_ratio, "turnover24": turnover24,
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


def build_universe(client, cfg, now):
    exchanges = client.get("/exchanges")
    code = find_exchange_code(exchanges, "bybit")
    if code is None:
        raise ApiError("could not find Bybit in Coinalyze /exchanges")
    markets = client.get("/future-markets")
    if not isinstance(markets, list) or not markets:
        raise ApiError("empty /future-markets response")
    cands, btc_symbol = [], None
    for m in markets:
        if str(m.get("exchange")) != code and str(m.get("exchange", "")).lower() != "bybit":
            continue
        if not m.get("is_perpetual") or str(m.get("quote_asset", "")).upper() != "USDT":
            continue
        base = str(m.get("base_asset", "")).upper()
        if base == "BTC" and btc_symbol is None:
            btc_symbol = m["symbol"]
        if base in EXCLUDED_BASES or not m.get("has_ohlcv_data", True) or not m.get("has_buy_sell_data", True):
            continue
        cands.append(m)
    log(f"Bybit exchange code {code}: {len(cands)} candidate USDT perps (BTC symbol: {btc_symbol})")
    if not cands:
        raise ApiError("no Bybit USDT perpetuals found - Coinalyze response format may have changed")

    by_sym = {m["symbol"]: m for m in cands}
    syms = list(by_sym)
    ranked = []
    for i in range(0, len(syms), 20):
        chunk = syms[i:i + 20]
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
    chosen = ranked[: cfg["universe_size"]]
    if len(chosen) < 10:
        raise ApiError(f"only {len(chosen)} coins passed the open-interest filter - refusing to overwrite universe")
    return {
        "generated": now.isoformat(), "exchange_code": code, "btc_symbol": btc_symbol,
        "symbols": [{
            "symbol": s, "base": by_sym[s].get("base_asset"), "denom": by_sym[s].get("oi_lq_vol_denominated_in"),
            "ticker": by_sym[s].get("symbol_on_exchange") or f"{by_sym[s].get('base_asset')}USDT",
            "has_ls": bool(by_sym[s].get("has_long_short_ratio_data", False)), "oi_usd": v,
        } for v, s in chosen],
    }


# ----------------------------------------------------------------------------- scan pipeline
def run_scan(cfg, client, uni, now):
    items = uni["symbols"]
    syms = [u["symbol"] for u in items]
    t_to = int(now.timestamp())
    t_from = t_to - cfg["lookback_days"] * 86400
    skipped = {}

    # Stage A: OI history for everyone (cheap build-up filter)
    oi_hist, errs = client.fetch_history("/open-interest-history", syms, "1hour", t_from, t_to, {"convert_to_usd": "false"})
    for s, e in errs.items():
        skipped[s] = f"OI fetch failed: {e}"
    prelim = {}
    for s in syms:
        if s in oi_hist:
            try:
                prelim[s] = prelim_oi_score(oi_hist[s])[0]
            except Skip as e:
                skipped[s] = str(e)
        elif s not in skipped:
            skipped[s] = "missing from response"
    if len(prelim) < max(5, 0.5 * len(syms)):
        raise FatalError(f"only {len(prelim)}/{len(syms)} coins returned usable OI data - Coinalyze problem or format change")

    top = sorted(prelim, key=prelim.get, reverse=True)[: cfg["stage_b_n"]]
    meta = {u["symbol"]: u for u in items}

    # Stage B: full data for the shortlist (+ BTC for the regime check)
    want_px = list(top) + ([uni["btc_symbol"]] if uni.get("btc_symbol") else [])
    px_hist, e1 = client.fetch_history("/ohlcv-history", want_px, "1hour", t_from, t_to)
    fr_hist, e2 = client.fetch_history("/funding-rate-history", top, "1hour", t_from, t_to)
    ls_syms = [s for s in top if meta[s].get("has_ls")]
    ls_hist, e3 = client.fetch_history("/long-short-ratio-history", ls_syms, "1hour", t_from, t_to) if ls_syms else ({}, {})
    for s, e in {**e3, **e2, **e1}.items():
        skipped.setdefault(s, f"fetch failed: {e}")

    btc = {"ok": False, "text": "BTC regime unknown (no BTC data)"}
    if uni.get("btc_symbol") and uni["btc_symbol"] in px_hist:
        try:
            bdf = build_frame(px_hist[uni["btc_symbol"]], None, None, None, now, max_stale_h=cfg["max_stale_h"])
            btc = btc_regime(bdf)
        except Skip:
            pass

    ranked = []
    for s in top:
        if s not in px_hist:
            skipped.setdefault(s, "no OHLCV returned")
            continue
        try:
            df = build_frame(px_hist[s], oi_hist.get(s), fr_hist.get(s), ls_hist.get(s), now,
                             denom=meta[s].get("denom"), max_stale_h=cfg["max_stale_h"])
            res = score_coin(df, cfg)
            res.update({"symbol": s, "base": meta[s].get("base") or s, "ticker": meta[s].get("ticker") or s,
                        "prelim": prelim[s]})
            ranked.append(res)
        except Skip as e:
            skipped[s] = str(e)
        except Exception as e:  # one coin must never kill the scan
            skipped[s] = f"unexpected {type(e).__name__}: {e}"
    if not ranked:
        raise FatalError("no coins could be scored (all skipped) - see skip reasons in the log")
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


def fmt_coin(i, c):
    m = c["m"]
    icon = {"IMMINENT": "⚡", "BUILDING": "\U0001f3d7", "WATCH": "\U0001f440"}[c["tier"]]
    esc = html.escape
    lines = [
        f"{i}. <b>{esc(str(c.get('ticker') or c['symbol']))}</b> {icon} {c['tier']} · score {c['score']:.0f}",
        f"   {esc(c['lean'])}",
        f"   OI {_f(m['oi4_chg'] * 100)}% 4h / {_f(m['oi1d_chg'] * 100)}% 24h (z {_f(m['oi4_z'])}) · price {_f(m['ret24'] * 100)}% 24h",
        f"   CVD 4h z {_f(m['imb4_z'])}{' DIVERGENCE' if m['cvd_div'] else ''} · funding {_f(m['fund_last'], '+.4f')} (z {_f(m['fund_z'])})",
        f"   Squeeze: 4H range pctile {_f(m['bbw_pct'] * 100, '.0f')} (low = coiled) · 1h vol {m['vol_ratio']:.1f}x · 1h range {m['range_ratio']:.1f}x",
    ]
    if c["flags"]:
        lines.append("   ⚠ " + esc(", ".join(c["flags"])))
    return "\n".join(lines)


def format_message(kind, ranked, btc, now, top_k, notes=None, new_imminent=None):
    head = {"alert": "⚡ <b>IMMINENT ALERT</b>", "digest": "\U0001f553 <b>4H DIGEST</b>", "heartbeat": "✅ <b>Scanner alive</b>"}[kind]
    s = sydney(now)
    out = [f"{head} — {s:%a %d %b %H:%M} Sydney", html.escape(btc["text"])]
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
    out.append("<i>Shortlist only: wait for your BOS + protected level, then enter.</i>")
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
              "imb4_z", "bbw_pct", "ret4", "ret24", "vol_ratio", "flags"]


def append_log(path, ranked, now):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists()
    with p.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(LOG_FIELDS)
        for c in ranked:
            m = c["m"]
            w.writerow([now.isoformat(timespec="minutes"), c["symbol"], c["tier"], f"{c['score']:.1f}", f"{c['setup']:.3f}",
                        f"{c['trigger']:.3f}", *[("" if math.isnan(m[k]) else f"{m[k]:.3f}") for k in
                                                 ("oi4_z", "oi1d_z", "oi2h_z", "fund_z", "lsr_z", "imb4_z", "bbw_pct")],
                        f"{m['ret4']:.4f}", f"{m['ret24']:.4f}", f"{m['vol_ratio']:.2f}", "|".join(c["flags"])])


# ----------------------------------------------------------------------------- commands
def cmd_universe(cfg, client):
    now = dt.datetime.now(UTC)
    uni = build_universe(client, cfg, now)
    save_json(cfg["data_dir"] / "universe.json", uni)
    log(f"universe.json saved: {len(uni['symbols'])} coins, top 10: " + ", ".join(u["base"] for u in uni["symbols"][:10]))
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
    state = load_json(sp, {})
    try:
        uni = load_json(cfg["data_dir"] / "universe.json", None)
        if not uni or not uni.get("symbols"):
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
    log(f"stats: {stats}")
    for s, why in sorted(res["skipped"].items()):
        log(f"  skipped {s}: {why}")
    for c in top:
        log(f"  {c['tier']:<8} {c['score']:5.1f} setup {c['setup']:.2f} trig {c['trigger']:.2f}  {c['symbol']}")

    notes = []
    age_h = _hours_since(uni.get("generated"), now)
    if age_h > 72:
        notes.append(f"Note: coin universe is {age_h / 24:.0f} days old - check the daily universe workflow.")
    if len(res["skipped"]) > 0.4 * stats["universe"]:
        notes.append(f"Note: {len(res['skipped'])}/{stats['universe']} coins skipped (data gaps).")

    kind, new_imm = decide_send(top, state, now, cfg)
    if dry:
        log("---- DRY RUN message (not sent) ----")
        log(re.sub(r"<[^>]+>", "", html.unescape(format_message(kind or "digest", ranked, btc, now, cfg["top_k"], notes, new_imm))))
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
        log("nothing new to send this hour")
    state["last_top"] = [c["symbol"] for c in top]
    state["last_tiers"] = {c["symbol"]: c["tier"] for c in top}
    state["last_scan"] = now.isoformat()
    save_json(sp, state)
    return 0


def diagnose(cfg):
    ok_all = True
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
                tg_send(token.strip(), chat.strip(), "✅ Scanner diagnose: Telegram test message")
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
        log(f"   PASS  API key accepted, {len(ex)} exchanges, Bybit code = {code}")
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
                         ("/funding-rate-history", ("c",)), ("/long-short-ratio-history", ("r",))):
            data, errs = client.fetch_history(ep, [sample], "1hour", t_to - 3 * 86400, t_to)
            h = data.get(sample, [])
            if not h:
                log(f"   {'FAIL' if ep in ('/open-interest-history', '/ohlcv-history') else 'WARN'}  {ep}: no data for {sample} {errs.get(sample, '')}")
                ok_all &= ep not in ("/open-interest-history", "/ohlcv-history")
                continue
            missing = [f for f in flds if f not in h[-1]]
            age = (t_to - h[-1]["t"]) / 3600
            log(f"   {'PASS' if not missing else 'FAIL'}  {ep}: {len(h)} points, newest {age:.1f}h old, fields {sorted(h[-1])}"
                + (f" MISSING {missing}" if missing else ""))
            ok_all &= not missing
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
    if mode not in ("scan", "scan-dry-run", "universe"):
        log(f"unknown mode {mode!r}; use scan | scan-dry-run | universe | diagnose")
        return 2
    client = Coinalyze(os.environ.get("COINALYZE_API_KEY", "").strip(), limiter=RateLimiter(cfg["calls_per_min"]), batch=cfg["batch"])
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    try:
        if mode == "universe":
            return cmd_universe(cfg, client)
        return cmd_scan(cfg, client, token, chat, dry=(mode == "scan-dry-run"))
    except ApiError as e:
        log(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
