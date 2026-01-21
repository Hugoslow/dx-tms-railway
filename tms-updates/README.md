# DX TMS Updates - Operational Day & Daily Reports

This update package adds:

1. **Operational Day Logic** - The system now recognises that trunking runs 10:30 to 10:30, not midnight to midnight
2. **5am Daily Reports** - Automatic "State of the Nation" snapshots for day-on-day comparison
3. **10:30am Reset** - Loads fresh movements for the new operational day

---

## What's Included

| File | Purpose |
|------|---------|
| `add-daily-reports-table.js` | Database migration - run once to add the reports table |
| `new-endpoints.js` | New API endpoints to add to your server.js |
| `CRON_SETUP_GUIDE.md` | Instructions for setting up the scheduled jobs |
| `reports-page.html` | Optional frontend page for viewing historical reports |

---

## Installation Steps

### Step 1: Run the Database Migration

Upload `add-daily-reports-table.js` to your project and run it once:

```bash
# In Railway console or locally
node add-daily-reports-table.js
```

This creates the `daily_reports` table. You'll see:
```
Adding daily_reports table...
✅ daily_reports table created successfully
✅ Migration logged to audit_log
```

### Step 2: Update server.js

Open your `server.js` file and:

1. **Add the helper functions** at the top (after your imports):
   - `getOperationalDay()`
   - `timeToMinutes()`
   - `calculateVariance()`

2. **Replace your existing `/api/reset-daily` endpoint** with the new version

3. **Add the new endpoints**:
   - `POST /api/generate-daily-report` - For 5am cron
   - `GET /api/daily-reports` - View report history
   - `GET /api/daily-reports/:date` - View specific report
   - `GET /api/daily-reports/compare/:date1/:date2` - Compare two days
   - `GET /api/operational-day` - Info about current operational day

4. **Commit and push** to trigger Railway deployment

### Step 3: Update Cron Jobs

Follow the `CRON_SETUP_GUIDE.md` to:

1. **Update** your existing reset job from 03:30 → **10:30**
2. **Add** a new 5am report generation job

---

## New Schedule Overview

```
┌─────────────────────────────────────────────────────────┐
│              OPERATIONAL DAY TIMELINE                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  10:30 ────────────────────────────────────────► 10:30  │
│    │                                                │    │
│    │   OPERATIONAL DAY "JANUARY 15"                │    │
│    │                                                │    │
│    ▼                                                ▼    │
│  Reset                                           Reset   │
│  loads                                           loads   │
│  Jan 15                                          Jan 16  │
│  movements                                       movements│
│                                                          │
│         22:00 ──────── 05:00 ─────► 10:30               │
│           │              │            │                  │
│       Night shift    5am Report    Day ends              │
│        starts        generated                           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Testing

### Test Report Generation Manually

```bash
curl -X POST https://your-domain.com/api/generate-daily-report \
  -H "x-reset-key: your-secret-key"
```

Expected response:
```json
{
  "message": "Daily report generated successfully",
  "operationalDay": "2026-01-15",
  "summary": {
    "totalMovements": 429,
    "completionRate": "87.5%",
    "departureOtp": "92.3%",
    "arrivalOtp": "88.7%",
    "delayed": 12
  }
}
```

### View Reports

```bash
# Get last 7 days
curl https://your-domain.com/api/daily-reports \
  -H "Authorization: Bearer YOUR_TOKEN"

# Compare two days
curl https://your-domain.com/api/daily-reports/compare/2026-01-14/2026-01-15 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Report Data Captured

Each 5am report stores:

| Category | Metrics |
|----------|---------|
| **Counts** | Total, Inbound, Outbound, Transfer |
| **Status** | Completed, In Progress, Scheduled, Delayed, Cancelled |
| **Performance** | On-time departures, Late departures, On-time arrivals, Late arrivals |
| **Percentages** | Completion rate, Departure OTP, Arrival OTP |
| **Averages** | Average departure variance, Average arrival variance |
| **Breakdowns** | By hub (JSON), By contractor (JSON) |
| **Details** | List of delayed movements with reasons |

---

## Questions?

Check the audit log for system activity:
- "5am Daily Report" entries show report generation
- "10:30 Daily Reset" entries show movement loading
