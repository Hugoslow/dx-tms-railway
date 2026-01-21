const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDatabase() {
  console.log('Initializing database with security features...');
  
  try {
    // Create tables
    await pool.query(`
      -- Users table with security fields
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100),
        role VARCHAR(20) NOT NULL DEFAULT 'viewer',
        location VARCHAR(100),
        active BOOLEAN DEFAULT true,
        force_password_change BOOLEAN DEFAULT false,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Sessions table for JWT tracking
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token_id VARCHAR(100) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        last_activity TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Trunk Schedule (master template)
      CREATE TABLE IF NOT EXISTS trunk_schedule (
        id SERIAL PRIMARY KEY,
        trunk_id VARCHAR(20) UNIQUE NOT NULL,
        route_ref VARCHAR(20),
        contractor VARCHAR(50),
        vehicle_type VARCHAR(20) DEFAULT 'ARTIC',
        origin VARCHAR(100) NOT NULL,
        destination VARCHAR(100) NOT NULL,
        scheduled_dep VARCHAR(5),
        scheduled_arr VARCHAR(5),
        direction VARCHAR(20) DEFAULT 'INBOUND',
        active BOOLEAN DEFAULT true,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Trunk Movements (daily live data)
      CREATE TABLE IF NOT EXISTS trunk_movements (
        id SERIAL PRIMARY KEY,
        trunk_id VARCHAR(20) NOT NULL,
        route_ref VARCHAR(20),
        contractor VARCHAR(50),
        vehicle_type VARCHAR(20) DEFAULT 'ARTIC',
        origin VARCHAR(100) NOT NULL,
        destination VARCHAR(100) NOT NULL,
        scheduled_dep VARCHAR(5),
        scheduled_arr VARCHAR(5),
        direction VARCHAR(20) DEFAULT 'INBOUND',
        status VARCHAR(20) DEFAULT 'scheduled',
        vehicle_reg VARCHAR(20),
        trailer VARCHAR(20),
        driver VARCHAR(100),
        driver_mobile VARCHAR(20),
        actual_dep VARCHAR(5),
        gate_arrival VARCHAR(5),
        dock_time VARCHAR(5),
        tip_start VARCHAR(5),
        tip_complete VARCHAR(5),
        bay VARCHAR(20),
        seal VARCHAR(50),
        fill_percent INTEGER DEFAULT 0,
        cages INTEGER DEFAULT 0,
        cancel_reason VARCHAR(100),
        movement_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Audit Log
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_name VARCHAR(100),
        action VARCHAR(100) NOT NULL,
        details TEXT,
        trunk_id VARCHAR(20),
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Indexes for performance
      CREATE INDEX IF NOT EXISTS idx_movements_date ON trunk_movements(movement_date);
      CREATE INDEX IF NOT EXISTS idx_movements_status ON trunk_movements(status);
      CREATE INDEX IF NOT EXISTS idx_movements_destination ON trunk_movements(destination);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    `);
    
    console.log('Tables created successfully');

    // Add new columns to existing users table if they don't exist
    const alterQueries = [
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT false",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP"
    ];
    
    for (const query of alterQueries) {
      try {
        await pool.query(query);
      } catch (e) {
        // Column might already exist, ignore error
      }
    }
    console.log('Security columns added to users table');

    // Check if admin user exists
    const adminCheck = await pool.query("SELECT * FROM users WHERE username = 'admin'");
    
    if (adminCheck.rows.length === 0) {
      // Create default admin user with force password change
      const adminPassword = await bcrypt.hash('Admin123!', 10);
      await pool.query(
        `INSERT INTO users (username, password_hash, full_name, email, role, location, force_password_change)
         VALUES ('admin', $1, 'System Administrator', 'admin@dxdelivery.com', 'admin', '', true)`,
        [adminPassword]
      );
      console.log('Admin user created (admin / Admin123!) - must change password on first login');
    } else {
      // Update existing admin to force password change if using old simple password
      const admin = adminCheck.rows[0];
      const isOldPassword = await bcrypt.compare('admin123', admin.password_hash);
      if (isOldPassword) {
        const newPassword = await bcrypt.hash('Admin123!', 10);
        await pool.query(
          "UPDATE users SET password_hash = $1, force_password_change = true WHERE username = 'admin'",
          [newPassword]
        );
        console.log('Admin password updated to Admin123! (force change on next login)');
      } else {
        console.log('Admin user already exists with custom password');
      }
    }

    // Check if schedule data exists
    const scheduleCheck = await pool.query("SELECT COUNT(*) FROM trunk_schedule");
    
    if (parseInt(scheduleCheck.rows[0].count) === 0) {
      console.log('No schedule data found. Run import-schedule.js to load trunk schedule.');
    } else {
      console.log(`Schedule contains ${scheduleCheck.rows[0].count} trunks`);
    }

    // Log initialization
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', 'Database Init', 'Database initialized with security features v2.0']
    );

    console.log('Database initialization complete!');
    
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    await pool.end();
  }
}

initDatabase();
