const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDatabase() {
  console.log('Initializing database...');
  
  try {
    // Create tables
    await pool.query(`
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100),
        role VARCHAR(20) NOT NULL DEFAULT 'viewer',
        location VARCHAR(100),
        active BOOLEAN DEFAULT true,
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
    `);
    
    console.log('Tables created successfully');

    // Check if admin user exists
    const adminCheck = await pool.query("SELECT * FROM users WHERE username = 'admin'");
    
    if (adminCheck.rows.length === 0) {
      // Create default admin user
      const adminPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        `INSERT INTO users (username, password_hash, full_name, email, role, location)
         VALUES ('admin', $1, 'System Administrator', 'admin@dxdelivery.com', 'admin', '')`,
        [adminPassword]
      );
      console.log('Admin user created (admin / admin123)');
    } else {
      console.log('Admin user already exists');
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
      ['System', 'Database Init', 'Database initialized successfully']
    );

    console.log('Database initialization complete!');
    
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    await pool.end();
  }
}

initDatabase();
