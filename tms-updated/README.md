# DX TMS Update - Operational Day Sorting & Daily Reports

## What's Changed

### 1. Operational Time Sorting (10:30 → 10:29)
All pages now sort movements starting from 10:30, not midnight:
- Schedule page
- Live Board
- Depot Departure
- Hub Arrival
- Hub Operations

**Before:** 00:00, 01:30, 03:00 ... 22:00, 23:00
**After:** 10:30, 11:00, 12:00 ... 22:00, 23:00, 00:00, 01:30, 03:00 ... 10:00

### 2. New Cron Schedule
| Time | Action |
|------|--------|
| **05:00** | Generate "State of the Nation" report |
| **10:30** | Reset and load fresh 429 movements |

### 3. Daily Reports (5am Snapshots)
New feature for day-on-day comparison of performance metrics.

---

## Installation Steps (Same as before!)

### Step 1: Replace Your Files
Copy the updated files into your `dx-tms-railway` folder:
- `server.js` → Replace your existing server.js
- `index.html` → Goes inside the `public` folder (replace existing)

### Step 2: Commit and Push to GitHub
```
git add .
git commit -m "Add operational day sorting and daily reports"
git push
```

Railway will automatically redeploy. The database table for reports will be created automatically.

### Step 3: Update Cron Jobs (cron-job.org)

**Change your existing reset job:**
- Change the time from `30 3 * * *` to `30 10 * * *` (10:30am)

**Add a new job for the 5am report:**
- Title: `DX TMS 5am Report`
- URL: `https://your-domain.com/api/generate-daily-report`
- Schedule: `0 5 * * *`
- Method: POST
- Header: `x-reset-key` = your secret key
- Timezone: Europe/London

---

## Files Included
| File | Where to put it |
|------|-----------------|
| `server.js` | `C:\Projects\dx-tms-railway\server.js` |
| `index.html` | `C:\Projects\dx-tms-railway\public\index.html` |
