// Migration: Add daily_reports table for 5am snapshots
// Run this once on your existing database

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function migrate() {
  console.log('Adding daily_reports table...');
  
  try {
    await pool.query(`
      -- Daily Reports table for 5am snapshots
      CREATE TABLE IF NOT EXISTS daily_reports (
        id SERIAL PRIMARY KEY,
        report_date DATE NOT NULL UNIQUE,
        operational_day DATE NOT NULL,
        
        -- Movement counts
        total_movements INTEGER DEFAULT 0,
        inbound_count INTEGER DEFAULT 0,
        outbound_count INTEGER DEFAULT 0,
        transfer_count INTEGER DEFAULT 0,
        
        -- Status breakdown at 5am
        completed_count INTEGER DEFAULT 0,
        in_progress_count INTEGER DEFAULT 0,
        scheduled_count INTEGER DEFAULT 0,
        delayed_count INTEGER DEFAULT 0,
        cancelled_count INTEGER DEFAULT 0,
        
        -- Performance metrics
        on_time_departures INTEGER DEFAULT 0,
        late_departures INTEGER DEFAULT 0,
        on_time_arrivals INTEGER DEFAULT 0,
        late_arrivals INTEGER DEFAULT 0,
        
        -- Calculated percentages
        completion_rate DECIMAL(5,2) DEFAULT 0,
        departure_otp DECIMAL(5,2) DEFAULT 0,
        arrival_otp DECIMAL(5,2) DEFAULT 0,
        
        -- Average variances (in minutes)
        avg_departure_variance INTEGER DEFAULT 0,
        avg_arrival_variance INTEGER DEFAULT 0,
        
        -- Breakdown by hub (stored as JSON)
        hub_breakdown JSONB,
        
        -- Breakdown by contractor (stored as JSON)
        contractor_breakdown JSONB,
        
        -- Any delayed movements details (stored as JSON)
        delayed_movements JSONB,
        
        -- Metadata
        generated_at TIMESTAMP DEFAULT NOW(),
        notes TEXT
      );

      -- Index for fast date lookups
      CREATE INDEX IF NOT EXISTS idx_daily_reports_date ON daily_reports(report_date);
      CREATE INDEX IF NOT EXISTS idx_daily_reports_operational_day ON daily_reports(operational_day);
    `);

    console.log('✅ daily_reports table created successfully');
    
    // Log the migration
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', 'Database Migration', 'Added daily_reports table for 5am snapshots']
    );
    
    console.log('✅ Migration logged to audit_log');
    
  } catch (err) {
    console.error('Migration error:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

migrate();
