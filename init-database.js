const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDatabase() {
  console.log('Initializing database with costing and PO features (v4.0)...');
  
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
        is_amendment BOOLEAN DEFAULT false,
        amendment_note TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Schedule Amendments (for tracking changes to master schedule)
      CREATE TABLE IF NOT EXISTS schedule_amendments (
        id SERIAL PRIMARY KEY,
        amendment_date DATE NOT NULL,
        trunk_id VARCHAR(20) NOT NULL,
        amendment_type VARCHAR(20) NOT NULL,
        original_values JSONB,
        new_values JSONB,
        reason TEXT,
        created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
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

      -- Daily Reports
      CREATE TABLE IF NOT EXISTS daily_reports (
        id SERIAL PRIMARY KEY,
        report_date DATE NOT NULL UNIQUE,
        operational_day DATE NOT NULL,
        total_movements INTEGER DEFAULT 0,
        inbound_count INTEGER DEFAULT 0,
        outbound_count INTEGER DEFAULT 0,
        transfer_count INTEGER DEFAULT 0,
        completed_count INTEGER DEFAULT 0,
        in_progress_count INTEGER DEFAULT 0,
        scheduled_count INTEGER DEFAULT 0,
        delayed_count INTEGER DEFAULT 0,
        cancelled_count INTEGER DEFAULT 0,
        on_time_departures INTEGER DEFAULT 0,
        late_departures INTEGER DEFAULT 0,
        on_time_arrivals INTEGER DEFAULT 0,
        late_arrivals INTEGER DEFAULT 0,
        completion_rate DECIMAL(5,2) DEFAULT 0,
        departure_otp DECIMAL(5,2) DEFAULT 0,
        arrival_otp DECIMAL(5,2) DEFAULT 0,
        avg_departure_variance INTEGER DEFAULT 0,
        avg_arrival_variance INTEGER DEFAULT 0,
        hub_breakdown JSONB,
        contractor_breakdown JSONB,
        delayed_movements JSONB,
        generated_at TIMESTAMP DEFAULT NOW(),
        notes TEXT
      );

      -- ============ COSTING & PO TABLES ============

      -- Contractors (subcontractors and internal)
      CREATE TABLE IF NOT EXISTS contractors (
        id SERIAL PRIMARY KEY,
        code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        address_line1 VARCHAR(100),
        address_line2 VARCHAR(100),
        city VARCHAR(50),
        postcode VARCHAR(20),
        contact_name VARCHAR(100),
        contact_email VARCHAR(100),
        contact_phone VARCHAR(30),
        po_email VARCHAR(100),
        vat_registered BOOLEAN DEFAULT true,
        vat_number VARCHAR(30),
        payment_terms INTEGER DEFAULT 30,
        is_internal BOOLEAN DEFAULT false,
        active BOOLEAN DEFAULT true,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Locations (hubs, depots, delivery points)
      CREATE TABLE IF NOT EXISTS locations (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        address_line1 VARCHAR(100),
        address_line2 VARCHAR(100),
        city VARCHAR(50),
        postcode VARCHAR(20),
        location_type VARCHAR(20) DEFAULT 'depot',
        active BOOLEAN DEFAULT true,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Route Costs (cost per route, per contractor, per day type)
      CREATE TABLE IF NOT EXISTS route_costs (
        id SERIAL PRIMARY KEY,
        route_ref VARCHAR(20) NOT NULL,
        contractor_code VARCHAR(20) NOT NULL REFERENCES contractors(code),
        day_type VARCHAR(20) NOT NULL DEFAULT 'weekday',
        base_cost DECIMAL(10,2) NOT NULL,
        effective_from DATE DEFAULT CURRENT_DATE,
        effective_to DATE,
        active BOOLEAN DEFAULT true,
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(route_ref, contractor_code, day_type, effective_from)
      );

      -- Company Settings (DX company details)
      CREATE TABLE IF NOT EXISTS company_settings (
        id SERIAL PRIMARY KEY,
        setting_key VARCHAR(50) UNIQUE NOT NULL,
        setting_value TEXT,
        setting_type VARCHAR(20) DEFAULT 'text',
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Bank Holidays (manually flagged dates)
      CREATE TABLE IF NOT EXISTS bank_holidays (
        id SERIAL PRIMARY KEY,
        holiday_date DATE UNIQUE NOT NULL,
        description VARCHAR(100),
        created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Purchase Orders
      CREATE TABLE IF NOT EXISTS purchase_orders (
        id SERIAL PRIMARY KEY,
        po_number VARCHAR(20) UNIQUE NOT NULL,
        contractor_id INTEGER NOT NULL REFERENCES contractors(id),
        week_commencing DATE NOT NULL,
        week_ending DATE NOT NULL,
        subtotal DECIMAL(10,2) DEFAULT 0,
        fsc_total DECIMAL(10,2) DEFAULT 0,
        vat_amount DECIMAL(10,2) DEFAULT 0,
        grand_total DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(20) DEFAULT 'draft',
        created_by INTEGER REFERENCES users(id),
        authorised_by INTEGER REFERENCES users(id),
        authorised_at TIMESTAMP,
        sent_at TIMESTAMP,
        sent_to VARCHAR(100),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Purchase Order Lines
      CREATE TABLE IF NOT EXISTS purchase_order_lines (
        id SERIAL PRIMARY KEY,
        po_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
        movement_date DATE NOT NULL,
        route_ref VARCHAR(20) NOT NULL,
        trunk_id VARCHAR(20),
        vehicle_type VARCHAR(20) DEFAULT 'ARTIC',
        day_type VARCHAR(20) NOT NULL,
        origin VARCHAR(100),
        destination VARCHAR(100),
        scheduled_dep VARCHAR(5),
        scheduled_arr VARCHAR(5),
        route_legs JSONB,
        base_cost DECIMAL(10,2) NOT NULL,
        fsc_amount DECIMAL(10,2) DEFAULT 0,
        line_total DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Credit Notes
      CREATE TABLE IF NOT EXISTS credit_notes (
        id SERIAL PRIMARY KEY,
        credit_number VARCHAR(20) UNIQUE NOT NULL,
        po_id INTEGER NOT NULL REFERENCES purchase_orders(id),
        contractor_id INTEGER NOT NULL REFERENCES contractors(id),
        reason TEXT NOT NULL,
        subtotal DECIMAL(10,2) DEFAULT 0,
        fsc_total DECIMAL(10,2) DEFAULT 0,
        vat_amount DECIMAL(10,2) DEFAULT 0,
        grand_total DECIMAL(10,2) DEFAULT 0,
        status VARCHAR(20) DEFAULT 'draft',
        created_by INTEGER REFERENCES users(id),
        authorised_by INTEGER REFERENCES users(id),
        authorised_at TIMESTAMP,
        sent_at TIMESTAMP,
        sent_to VARCHAR(100),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Credit Note Lines
      CREATE TABLE IF NOT EXISTS credit_note_lines (
        id SERIAL PRIMARY KEY,
        credit_id INTEGER NOT NULL REFERENCES credit_notes(id) ON DELETE CASCADE,
        original_po_line_id INTEGER REFERENCES purchase_order_lines(id),
        movement_date DATE NOT NULL,
        route_ref VARCHAR(20) NOT NULL,
        trunk_id VARCHAR(20),
        reason VARCHAR(100),
        base_cost DECIMAL(10,2) NOT NULL,
        fsc_amount DECIMAL(10,2) DEFAULT 0,
        line_total DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- PO Sequence Counter
      CREATE TABLE IF NOT EXISTS po_sequence (
        id SERIAL PRIMARY KEY,
        year INTEGER NOT NULL,
        last_number INTEGER DEFAULT 0,
        UNIQUE(year)
      );

      -- Credit Note Sequence Counter
      CREATE TABLE IF NOT EXISTS credit_sequence (
        id SERIAL PRIMARY KEY,
        year INTEGER NOT NULL,
        last_number INTEGER DEFAULT 0,
        UNIQUE(year)
      );

      -- Indexes for performance
      CREATE INDEX IF NOT EXISTS idx_movements_date ON trunk_movements(movement_date);
      CREATE INDEX IF NOT EXISTS idx_movements_status ON trunk_movements(status);
      CREATE INDEX IF NOT EXISTS idx_movements_destination ON trunk_movements(destination);
      CREATE INDEX IF NOT EXISTS idx_movements_route_ref ON trunk_movements(route_ref);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_route_costs_route ON route_costs(route_ref);
      CREATE INDEX IF NOT EXISTS idx_route_costs_contractor ON route_costs(contractor_code);
      CREATE INDEX IF NOT EXISTS idx_po_contractor ON purchase_orders(contractor_id);
      CREATE INDEX IF NOT EXISTS idx_po_week ON purchase_orders(week_commencing);
      CREATE INDEX IF NOT EXISTS idx_po_status ON purchase_orders(status);
      CREATE INDEX IF NOT EXISTS idx_bank_holidays_date ON bank_holidays(holiday_date);
    `);
    
    console.log('Tables created successfully');

    // Add new columns to existing tables if they don't exist
    const alterQueries = [
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN DEFAULT false",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP",
      "ALTER TABLE trunk_movements ADD COLUMN IF NOT EXISTS is_amendment BOOLEAN DEFAULT false",
      "ALTER TABLE trunk_movements ADD COLUMN IF NOT EXISTS amendment_note TEXT"
    ];
    
    for (const query of alterQueries) {
      try {
        await pool.query(query);
      } catch (e) {
        // Column might already exist, ignore error
      }
    }
    console.log('Schema columns updated');

    // Initialize company settings if not exists
    const settingsToInit = [
      { key: 'company_name', value: 'DX Network Services Ltd', type: 'text' },
      { key: 'company_address_line1', value: '', type: 'text' },
      { key: 'company_address_line2', value: '', type: 'text' },
      { key: 'company_city', value: '', type: 'text' },
      { key: 'company_postcode', value: '', type: 'text' },
      { key: 'invoice_address_line1', value: '', type: 'text' },
      { key: 'invoice_address_line2', value: '', type: 'text' },
      { key: 'invoice_city', value: '', type: 'text' },
      { key: 'invoice_postcode', value: '', type: 'text' },
      { key: 'query_contact_name', value: '', type: 'text' },
      { key: 'query_contact_email', value: '', type: 'text' },
      { key: 'query_contact_phone', value: '', type: 'text' },
      { key: 'vat_rate', value: '20', type: 'number' },
      { key: 'fuel_surcharge_percent', value: '15', type: 'number' },
      { key: 'payment_terms_days', value: '30', type: 'number' },
      { key: 'payment_terms_text', value: 'Payment due within 30 days of invoice date', type: 'text' }
    ];

    for (const setting of settingsToInit) {
      try {
        await pool.query(
          `INSERT INTO company_settings (setting_key, setting_value, setting_type) 
           VALUES ($1, $2, $3) 
           ON CONFLICT (setting_key) DO NOTHING`,
          [setting.key, setting.value, setting.type]
        );
      } catch (e) {
        // Ignore if exists
      }
    }
    console.log('Company settings initialized');

    // Initialize PO sequence for current year
    const currentYear = new Date().getFullYear();
    await pool.query(
      `INSERT INTO po_sequence (year, last_number) VALUES ($1, 0) ON CONFLICT (year) DO NOTHING`,
      [currentYear]
    );
    await pool.query(
      `INSERT INTO credit_sequence (year, last_number) VALUES ($1, 0) ON CONFLICT (year) DO NOTHING`,
      [currentYear]
    );
    console.log('PO/Credit sequences initialized');

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
      ['System', 'Database Init', 'Database initialized with costing features v4.0']
    );

    console.log('Database initialization complete!');
    
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    await pool.end();
  }
}

initDatabase();
