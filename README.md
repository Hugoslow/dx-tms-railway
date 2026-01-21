# DX Trunking Management System

Real-time trunking operations management system built with Node.js, Express, and PostgreSQL.

## Features

- **Real-time tracking** of 429 trunk movements
- **Multi-user** with role-based permissions (Viewer, Depot, Gatehouse, Hub Ops, Supervisor, Admin)
- **Live updates** across all users (30-second auto-refresh)
- **Full audit trail** of all actions
- **Sortable/filterable** data views

---

## Deployment to Railway (Step-by-Step)

### Step 1: Push Code to GitHub

1. Create a new repository on GitHub (e.g., `dx-tms`)
2. Push this folder to the repository:

```bash
cd dx-tms-railway
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/dx-tms.git
git push -u origin main
```

### Step 2: Create Railway Project

1. Go to [railway.app](https://railway.app) and log in
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Choose your `dx-tms` repository
5. Railway will auto-detect it's a Node.js app

### Step 3: Add PostgreSQL Database

1. In your Railway project, click **"+ New"**
2. Select **"Database"** → **"PostgreSQL"**
3. Wait for it to provision (takes ~30 seconds)
4. Railway automatically links the DATABASE_URL to your app

### Step 4: Set Environment Variables

1. Click on your web service (not the database)
2. Go to **"Variables"** tab
3. Add these variables:
   - `NODE_ENV` = `production`
   - `RESET_SECRET_KEY` = `your-random-secret-here` (make up a long random string)

### Step 5: Initialize Database

1. Go to **"Settings"** tab on your web service
2. Under **"Deploy"**, find **"Custom Start Command"**
3. Temporarily change it to: `node init-database.js && node import-schedule.js && node server.js`
4. Click **"Deploy"** to trigger a deployment
5. Check the logs - you should see "Database initialized" and "429 trunks imported"
6. **IMPORTANT**: After successful init, change the start command back to just: `node server.js`

### Step 6: Test Your Deployment

1. Railway gives you a URL like `dx-tms-production.up.railway.app`
2. Open it in your browser
3. Login with: **admin** / **admin123**
4. You should see 429 trunks loaded!

---

## Connect Your GoDaddy Domain

### Step 1: Get Railway's Domain Info

1. In Railway, go to your web service
2. Click **"Settings"** → **"Networking"** → **"Generate Domain"**
3. Note the generated domain (e.g., `dx-tms-production.up.railway.app`)
4. Click **"+ Custom Domain"**
5. Enter your domain (e.g., `tms.yourdomain.com`)
6. Railway shows you the CNAME target

### Step 2: Configure GoDaddy DNS

1. Log into GoDaddy
2. Go to **DNS Management** for your domain
3. Add a **CNAME record**:
   - **Name**: `tms` (or whatever subdomain you want)
   - **Value**: The Railway domain (e.g., `dx-tms-production.up.railway.app`)
   - **TTL**: 600 seconds
4. Wait 5-30 minutes for DNS propagation

### Step 3: Verify

1. Visit your custom domain (e.g., `https://tms.yourdomain.com`)
2. Railway handles SSL automatically

---

## Setting Up Daily Resets (Optional)

To automatically load fresh schedule data each day, set up a cron job:

### Using Railway Cron (Recommended)

1. Create a new service in Railway
2. Add this as a scheduled task that runs at 03:30 and 10:30:

```bash
curl -X POST https://your-domain.com/api/reset-daily \
  -H "x-reset-key: your-secret-key-here"
```

### Using External Cron Service

Use a free service like [cron-job.org](https://cron-job.org):

1. Create account
2. Add new cron job
3. URL: `https://your-domain.com/api/reset-daily`
4. Method: POST
5. Header: `x-reset-key: your-secret-key-here`
6. Schedule: `30 3 * * *` (03:30 daily) and `30 10 * * *` (10:30 daily)

---

## File Structure

```
dx-tms-railway/
├── server.js           # Express API server
├── init-database.js    # Creates database tables
├── import-schedule.js  # Imports 429 trunk routes
├── trunk-data.json     # Trunk schedule data
├── package.json        # Dependencies
├── .env.example        # Environment variables template
├── public/
│   └── index.html      # Frontend application
└── README.md           # This file
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/login | User login |
| GET | /api/movements | Get today's movements |
| PATCH | /api/movements/:id | Update movement |
| POST | /api/movements | Add new movement |
| GET | /api/audit | Get audit log |
| GET | /api/users | Get all users |
| POST | /api/reset-daily | Reset daily data |
| GET | /api/stats | Get dashboard stats |

---

## Default Login

- **Username**: admin
- **Password**: admin123

**Change this immediately after deployment!**

---

## Troubleshooting

### "Database connection error"
- Check DATABASE_URL is set correctly
- Ensure PostgreSQL addon is provisioned

### "No movements showing"
- Run the import script: `node import-schedule.js`
- Check the audit log for "Schedule Import" entry

### "Custom domain not working"
- Wait for DNS propagation (up to 30 mins)
- Verify CNAME record is correct in GoDaddy
- Check Railway custom domain settings

---

## Support

For issues, contact the development team or raise an issue on GitHub.
