const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected:', res.rows[0].now);
  }
});

// ============ AUTH ENDPOINTS ============

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(username) = LOWER($1) AND active = true',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Log the login
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [user.full_name, 'Login', `${user.username} logged in`]
    );
    
    res.json({
      username: user.username,
      fullName: user.full_name,
      role: user.role,
      location: user.location,
      email: user.email
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ TRUNK MOVEMENTS ENDPOINTS ============

// Get all today's movements
app.get('/api/movements', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM trunk_movements 
       WHERE movement_date = CURRENT_DATE 
       ORDER BY scheduled_dep ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get movements error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single movement
app.get('/api/movements/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM trunk_movements WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Movement not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Get movement error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update movement (status changes, departures, arrivals etc)
app.patch('/api/movements/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const userName = req.headers['x-user-name'] || 'System';
    
    // Build dynamic update query
    const fields = [];
    const values = [];
    let paramCount = 1;
    
    const allowedFields = [
      'status', 'vehicle_reg', 'trailer', 'driver', 'driver_mobile',
      'actual_dep', 'gate_arrival', 'dock_time', 'tip_start', 'tip_complete',
      'bay', 'seal', 'fill_percent', 'cages', 'cancel_reason'
    ];
    
    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    }
    
    if (fields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    fields.push(`updated_at = NOW()`);
    values.push(id);
    
    const query = `UPDATE trunk_movements SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`;
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Movement not found' });
    }
    
    // Log the action
    const movement = result.rows[0];
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details, trunk_id) VALUES ($1, $2, $3, $4)',
      [userName, `Status: ${movement.status}`, `${movement.trunk_id}: ${movement.origin} → ${movement.destination}`, movement.trunk_id]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update movement error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new trunk movement
app.post('/api/movements', async (req, res) => {
  try {
    const {
      trunk_id, route_ref, contractor, vehicle_type, origin, destination,
      scheduled_dep, scheduled_arr, direction, status = 'scheduled'
    } = req.body;
    const userName = req.headers['x-user-name'] || 'System';
    
    const result = await pool.query(
      `INSERT INTO trunk_movements 
       (trunk_id, route_ref, contractor, vehicle_type, origin, destination, 
        scheduled_dep, scheduled_arr, direction, status, movement_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_DATE)
       RETURNING *`,
      [trunk_id, route_ref, contractor, vehicle_type, origin, destination,
       scheduled_dep, scheduled_arr, direction, status]
    );
    
    // Log the action
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details, trunk_id) VALUES ($1, $2, $3, $4)',
      [userName, 'Trunk added', `${trunk_id}: ${origin} → ${destination}`, trunk_id]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Add movement error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ TRUNK SCHEDULE (MASTER) ENDPOINTS ============

// Get all scheduled trunks (master template)
app.get('/api/schedule', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM trunk_schedule WHERE active = true ORDER BY scheduled_dep ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get schedule error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ AUDIT LOG ENDPOINTS ============

// Get audit log
app.get('/api/audit', async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const result = await pool.query(
      'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get audit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add audit entry
app.post('/api/audit', async (req, res) => {
  try {
    const { user_name, action, details, trunk_id } = req.body;
    const result = await pool.query(
      'INSERT INTO audit_log (user_name, action, details, trunk_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [user_name, action, details, trunk_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Add audit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ USER MANAGEMENT ENDPOINTS ============

// Get all users (admin only)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, full_name, email, role, location, active, created_at FROM users ORDER BY full_name'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle user active status
app.patch('/api/users/:id/toggle', async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE users SET active = NOT active WHERE id = $1 RETURNING id, username, full_name, active',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Toggle user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create user
app.post('/api/users', async (req, res) => {
  try {
    const { username, password, full_name, email, role, location } = req.body;
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, full_name, email, role, location)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, full_name, email, role, location, active`,
      [username, password_hash, full_name, email, role, location]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create user error:', err);
    if (err.code === '23505') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Server error' });
    }
  }
});

// ============ DAILY RESET ENDPOINT ============

// Reset daily movements from schedule (called by cron or manual)
app.post('/api/reset-daily', async (req, res) => {
  try {
    const secretKey = req.headers['x-reset-key'];
    if (secretKey !== process.env.RESET_SECRET_KEY) {
      return res.status(403).json({ error: 'Invalid reset key' });
    }
    
    // Archive yesterday's movements (optional - could move to history table)
    // For now, just delete completed movements from previous days
    await pool.query(
      `DELETE FROM trunk_movements WHERE movement_date < CURRENT_DATE`
    );
    
    // Check what's already in today's movements (preserve in-transit)
    const existing = await pool.query(
      `SELECT trunk_id FROM trunk_movements WHERE movement_date = CURRENT_DATE`
    );
    const existingIds = existing.rows.map(r => r.trunk_id);
    
    // Copy from schedule to movements for today (only new ones)
    const result = await pool.query(
      `INSERT INTO trunk_movements 
       (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
        scheduled_dep, scheduled_arr, direction, status, movement_date)
       SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
              scheduled_dep, scheduled_arr, direction, 'scheduled', CURRENT_DATE
       FROM trunk_schedule
       WHERE active = true
       ${existingIds.length > 0 ? `AND trunk_id NOT IN (${existingIds.map((_, i) => `$${i + 1}`).join(',')})` : ''}
       RETURNING trunk_id`,
      existingIds.length > 0 ? existingIds : []
    );
    
    // Log the reset
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', 'Daily Reset', `Loaded ${result.rows.length} movements for today`]
    );
    
    res.json({ message: `Reset complete. Loaded ${result.rows.length} movements.` });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ STATS ENDPOINT ============

app.get('/api/stats', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status != 'cancelled') as total,
        COUNT(*) FILTER (WHERE direction = 'INBOUND' AND status != 'cancelled') as inbound,
        COUNT(*) FILTER (WHERE direction = 'OUTBOUND' AND status != 'cancelled') as outbound,
        COUNT(*) FILTER (WHERE direction = 'TRANSFER' AND status != 'cancelled') as transfer,
        COUNT(*) FILTER (WHERE status = 'scheduled') as scheduled,
        COUNT(*) FILTER (WHERE status = 'loading') as loading,
        COUNT(*) FILTER (WHERE status = 'departed') as departed,
        COUNT(*) FILTER (WHERE status = 'in-transit') as in_transit,
        COUNT(*) FILTER (WHERE status = 'arrived') as arrived,
        COUNT(*) FILTER (WHERE status IN ('docked', 'tipping', 'complete')) as complete,
        COUNT(*) FILTER (WHERE status = 'delayed') as delayed,
        COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled
      FROM trunk_movements
      WHERE movement_date = CURRENT_DATE
    `);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ SERVE FRONTEND ============

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ START SERVER ============

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DX TMS Server running on port ${PORT}`);
});
