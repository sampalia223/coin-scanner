# Altcoin volatility scanner (Coinalyze -> Telegram, runs free on GitHub Actions)

Every hour it ranks ~60 liquid Bybit USDT perps (BTC/ETH excluded) on open-interest build-up, CVD, funding/long-short crowding,
4H compression and 1H acceleration, then sends your top 5 to Telegram. It is a shortlist, not a signal: you still wait for your BOS.

## Setup (about 20 minutes, no coding)

**1. Get your three secrets**
- Coinalyze API key: coinalyze.net -> your account -> API key page.
- Telegram bot token: you already have it (from @BotFather).
- Telegram chat id: open your bot in Telegram, press **Start**, send "hi". Then message **@userinfobot** to get your id (a number).

**2. Add them to GitHub** (your repo -> Settings -> Secrets and variables -> Actions -> New repository secret). Names must be exact:
`COINALYZE_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Paste only the value, no spaces or quotes.

**3. Allow the bot to save its state** (repo -> Settings -> Actions -> General -> Workflow permissions -> **Read and write permissions** -> Save).

**4. Clean the repo, then upload**
- Delete the old Gemini files and any old workflow in `.github/workflows/` so they don't keep running.
- Unzip this package. In the repo click **Add file -> Upload files** and drag in everything (`scanner.py`, `requirements.txt`, `data`, `.github`). Commit.
- If the hidden `.github` folder doesn't upload: **Add file -> Create new file**, type `.github/workflows/scan.yml` as the name (the slashes create the folders), paste the file's contents, commit. Repeat for `universe.yml`.
- The files must sit at the top level of the repo, not inside another folder.

**5. First runs, in this order** (Actions tab -> pick the workflow on the left -> **Run workflow**)
1. `universe`: builds the coin list. Takes 10-15 min (free API limit is 40 calls/min). Wait for the green tick.
2. `scan` with mode **diagnose**: tests Telegram and Coinalyze separately. You should get a Telegram message and `RESULT: ALL GOOD`.
3. `scan` with mode **scan-dry-run**: prints what the alert would look like in the log, sends nothing.
4. `scan` with mode **scan**: sends a real alert. After this the hourly schedule just runs.

If anything fails, open the run log and send me the lines starting with `FAIL`. The log never prints your secrets.

## What you receive
- **IMMINENT alert**: sent immediately when a coin newly qualifies (strong 1D/4H set-up AND the 1H is waking up). 4-hour cooldown per coin.
- **4H digest**: the full top 5 at each 4-hour UTC boundary (11am, 3pm, 7pm, 11pm, 3am, 7am Sydney during daylight saving).
- **Heartbeat** if nothing was sent for 24h, and a **failure notice** if the scanner breaks.
- Tiers: IMMINENT, BUILDING (set-up ready, 1H quiet), WATCH (best of the rest). A coin that already moved >6% in 4h or >15% in 24h is tagged LATE and demoted to WATCH.

## Free-tier cost (important)
Each run uses about 100 API calls (~3 min). 24 runs x 30 days is roughly 2,300 Actions minutes a month, plus the daily universe job (~400).
- **Public repo: free and unlimited.** Your secrets stay hidden; only code, the coin ranking log and state are visible. Easiest option.
- **Private repo: free allowance is about 2,000 min/month**, so change the schedule in `scan.yml` to every 2 hours: `cron: "3 */2 * * *"`.
Coinalyze free key = $0. Telegram = $0.

## Limits worth knowing
- Bybit and Binance block GitHub's US servers, so this uses Coinalyze's Bybit data (no blocking). MEXC is not scanned yet.
- Coinalyze keeps only ~60 days of hourly history, so the 1D view is built from 30 days of hourly data.
- Thresholds are untuned starting points. `data/scan_log.csv` records every scan; after 2-3 weeks check which scores preceded real moves and adjust the weights at the top of `scanner.py`.
- Positioning shows fuel, not direction or timing. The "lean" is a probability hint, not a call.
- GitHub can delay scheduled runs 5-30 min and pauses schedules on repos with no activity for 60 days. Silence for 24h means check the Actions tab.

## Optional settings (environment variables in the workflow)
`UNIVERSE_SIZE` (60), `STAGE_B_N` (12, coins given the full analysis each run), `TOP_K` (5), `MIN_TURNOVER_USD` (2,000,000), `COOLDOWN_HOURS` (4).
