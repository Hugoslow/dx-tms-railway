# Cron Job Setup for DX TMS

## New Schedule

| Time | Action | Endpoint |
|------|--------|----------|
| **05:00** | Generate daily "State of the Nation" report | `/api/generate-daily-report` |
| **10:30** | Reset and load fresh movements for new operational day | `/api/reset-daily` |

---

## Option 1: cron-job.org (Recommended - Free)

### Step 1: Create Account
Go to https://cron-job.org and create a free account.

### Step 2: Add 5:00am Report Job

1. Click **"CREATE CRONJOB"**
2. Fill in:
   - **Title**: `DX TMS 5am Daily Report`
   - **URL**: `https://your-domain.com/api/generate-daily-report`
   - **Schedule**: Custom → `0 5 * * *`
   - **Timezone**: Select `Europe/London` (important for UK time!)
3. Click **"ADVANCED"** tab
4. Under **"Request Method"**: Select `POST`
5. Under **"Request Headers"**: Add:
   - **Header name**: `x-reset-key`
   - **Header value**: `your-secret-key-here` (same as your RESET_SECRET_KEY)
6. Click **"CREATE"**

### Step 3: Add 10:30am Reset Job

1. Click **"CREATE CRONJOB"**
2. Fill in:
   - **Title**: `DX TMS 10:30 Daily Reset`
   - **URL**: `https://your-domain.com/api/reset-daily`
   - **Schedule**: Custom → `30 10 * * *`
   - **Timezone**: Select `Europe/London`
3. Click **"ADVANCED"** tab
4. Under **"Request Method"**: Select `POST`
5. Under **"Request Headers"**: Add:
   - **Header name**: `x-reset-key`
   - **Header value**: `your-secret-key-here`
6. Click **"CREATE"**

---

## Option 2: Railway Cron Service

If you prefer to keep everything in Railway:

### Step 1: Create a New Service

1. In your Railway project, click **"+ New"**
2. Select **"Empty Service"**
3. Name it `tms-cron`

### Step 2: Add a Dockerfile

Create a simple cron container:

```dockerfile
FROM alpine:latest
RUN apk add --no-cache curl tzdata
ENV TZ=Europe/London

# Create cron job file
RUN echo "0 5 * * * curl -X POST -H 'x-reset-key: YOUR_SECRET_KEY' https://your-domain.com/api/generate-daily-report" >> /etc/crontabs/root
RUN echo "30 10 * * * curl -X POST -H 'x-reset-key: YOUR_SECRET_KEY' https://your-domain.com/api/reset-daily" >> /etc/crontabs/root

CMD ["crond", "-f", "-l", "2"]
```

### Step 3: Deploy

Push this to a GitHub repo and connect it to the Railway service.

---

## Option 3: Manual Testing

You can manually trigger either endpoint for testing:

### Test 5am Report Generation
```bash
curl -X POST https://your-domain.com/api/generate-daily-report \
  -H "x-reset-key: your-secret-key-here"
```

### Test 10:30am Reset
```bash
curl -X POST https://your-domain.com/api/reset-daily \
  -H "x-reset-key: your-secret-key-here"
```

---

## Understanding the Operational Day

The system now uses an "operational day" concept:

```
Operational Day "January 15"
├── Starts: January 15 @ 10:30
├── Night shift: 22:00 - 06:00
├── 5am Report: January 16 @ 05:00 (captures night's work)
└── Ends: January 16 @ 10:30 (new day loads)
```

This means:
- A trunk departing at 23:00 on Jan 15 and arriving at 02:00 on Jan 16 is all part of "Jan 15's operational day"
- The 5am report captures the state BEFORE the 10:30 reset
- Day-on-day comparisons are consistent because you're comparing full operational cycles

---

## Viewing Reports

Once reports are being generated, you can access them via the API:

### Get Last 7 Days of Reports
```
GET /api/daily-reports
GET /api/daily-reports?days=14
```

### Get Specific Date
```
GET /api/daily-reports/2026-01-15
```

### Compare Two Days
```
GET /api/daily-reports/compare/2026-01-14/2026-01-15
```

---

## Troubleshooting

### Reports not generating?
1. Check cron-job.org dashboard for execution history
2. Check your Railway logs for errors
3. Verify the `RESET_SECRET_KEY` matches exactly

### Wrong timezone?
- Ensure cron-job.org is set to `Europe/London`
- Railway uses UTC by default - account for BST/GMT differences

### Missing movements?
- Check the audit log for "10:30 Daily Reset" entries
- Verify `trunk_schedule` table has active = true entries
