# DX TMS Update - Complete Feature Update

## What's Changed

### 1. Operational Time Sorting (10:30 → 10:29)
All pages now sort movements starting from 10:30, not midnight.

### 2. Role-Based Tab Access
| Tab | Viewer | Depot | Gatehouse | Hub-Ops | Supervisor | Admin |
|-----|--------|-------|-----------|---------|------------|-------|
| Dashboard | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Live Board | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Schedule | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Depot Departure | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Hub Arrival | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Hub Operations | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Audit Log | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Metrics | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Users | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

### 3. Depot Origin Filter
- On Depot Departures, you must now select which depot you're departing from
- Only shows trunks from that depot (not all 400+)
- Makes it much easier for depot staff to find their trunks

### 4. Edit/Amend Trunk (Today Only)
- Edit button on Schedule page for each trunk
- Can change: Contractor, Vehicle Type, Vehicle Reg, Trailer, Driver, Scheduled Dep/Arr
- Changes only affect today's movement, not the master schedule
- Available to: Depot, Hub-Ops, Supervisor, Admin

### 5. Daily Reports (5am Snapshots) - Added to Metrics Page
- View historical reports (7/14/30 days)
- See completion rate, OTP, delays for each day
- Detailed breakdown by Hub and Contractor
- Day-on-day comparison tool

### 6. New Cron Schedule
| Time | Action |
|------|--------|
| **05:00** | Generate "State of the Nation" report |
| **10:30** | Reset and load fresh 429 movements |

---

## Installation Steps

### Step 1: Replace Your Files
Copy the updated files into your `dx-tms-railway` folder:
- `server.js` → `C:\Projects\dx-tms-railway\server.js` (replace existing)
- `index.html` → `C:\Projects\dx-tms-railway\public\index.html` (replace existing)

### Step 2: Commit and Push to GitHub
```
git add .
git commit -m "Role-based access, depot filter, edit trunk, daily reports"
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
