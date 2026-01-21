const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// JWT Secret - in production, use a long random string in environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'dx-tms-secret-key-change-in-production-2026';
const JWT_EXPIRY = '8h';
const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINS = 15;

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

// ============ RATE LIMITING ============

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict login rate limit
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 login attempts per minute
  message: { error: 'Too many login attempts, please wait a minute' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', loginLimiter);

// ============ PASSWORD VALIDATION ============

function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push('at least 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('one uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('one lowercase letter');
  if (!/[0-9]/.test(password)) errors.push('one number');
  return errors;
}

// ============ JWT MIDDLEWARE ============

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Check if session is still valid in database
    try {
      const session = await pool.query(
        'SELECT * FROM sessions WHERE token_id = $1 AND expires_at > NOW()',
        [decoded.tokenId]
      );
      
      if (session.rows.length === 0) {
        return res.status(401).json({ error: 'Session expired or invalidated' });
      }
      
      // Update last activity
      await pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token_id = $1',
        [decoded.tokenId]
      );
      
      req.user = decoded;
      next();
    } catch (dbErr) {
      console.error('Session check error:', dbErr);
      return res.status(500).json({ error: 'Server error' });
    }
  });
}

// ============ ROLE-BASED ACCESS CONTROL ============

const rolePermissions = {
  'viewer': { canView: true, canLogDeparture: false, canLogArrival: false, canUpdateOps: false, canManageTrunks: false, canManageUsers: false },
  'depot': { canView: true, canLogDeparture: true, canLogArrival: false, canUpdateOps: false, canManageTrunks: false, canManageUsers: false },
  'gatehouse': { canView: true, canLogDeparture: false, canLogArrival: true, canUpdateOps: false, canManageTrunks: false, canManageUsers: false },
  'hub-ops': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: false },
  'supervisor': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: false },
  'admin': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: true }
};

function requirePermission(permission) {
  return (req, res, next) => {
    const userRole = req.user?.role;
    if (!userRole || !rolePermissions[userRole] || !rolePermissions[userRole][permission]) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    next();
  };
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user?.role)) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    next();
  };
}

// ============ AUTH ENDPOINTS ============

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    
    if (result.rows.length === 0) {
      // Log failed attempt
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        ['Unknown', 'Failed Login', `Unknown username: ${username}`]
      );
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minsRemaining = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        [user.full_name, 'Login Blocked', `Account locked, ${minsRemaining} mins remaining`]
      );
      return res.status(423).json({ error: `Account locked. Try again in ${minsRemaining} minutes.` });
    }
    
    // Check if account is active
    if (!user.active) {
      return res.status(401).json({ error: 'Account disabled. Contact administrator.' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      // Increment failed attempts
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      
      if (newAttempts >= LOCKOUT_ATTEMPTS) {
        // Lock the account
        const lockUntil = new Date(Date.now() + LOCKOUT_DURATION_MINS * 60 * 1000);
        await pool.query(
          'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
          [newAttempts, lockUntil, user.id]
        );
        await pool.query(
          'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
          [user.full_name, 'Account Locked', `Locked after ${LOCKOUT_ATTEMPTS} failed attempts`]
        );
        return res.status(423).json({ error: `Account locked for ${LOCKOUT_DURATION_MINS} minutes after too many failed attempts.` });
      } else {
        await pool.query(
          'UPDATE users SET failed_login_attempts = $1 WHERE id = $2',
          [newAttempts, user.id]
        );
        await pool.query(
          'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
          [user.full_name, 'Failed Login', `Attempt ${newAttempts} of ${LOCKOUT_ATTEMPTS}`]
        );
      }
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Successful login - reset failed attempts
    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
      [user.id]
    );
    
    // Generate unique token ID for session tracking
    const tokenId = require('crypto').randomUUID();
    
    // Create JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username, 
        fullName: user.full_name,
        role: user.role, 
        location: user.location,
        tokenId: tokenId
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    
    // Store session in database
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours
    await pool.query(
      'INSERT INTO sessions (user_id, token_id, expires_at, last_activity) VALUES ($1, $2, $3, NOW())',
      [user.id, tokenId, expiresAt]
    );
    
    // Log successful login
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [user.full_name, 'Login', 'Successful login']
    );
    
    res.json({
      token,
      user: {
        username: user.username,
        fullName: user.full_name,
        role: user.role,
        location: user.location,
        email: user.email,
        forcePasswordChange: user.force_password_change || false
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM sessions WHERE token_id = $1', [req.user.tokenId]);
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'Logout', 'User logged out']
    );
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Validate new password
    const errors = validatePassword(newPassword);
    if (errors.length > 0) {
      return res.status(400).json({ error: `Password must contain ${errors.join(', ')}` });
    }
    
    // Get current user
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        [user.full_name, 'Password Change Failed', 'Incorrect current password']
      );
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newHash = await bcrypt.hash(newPassword, 10);
    
    // Update password and clear force change flag
    await pool.query(
      'UPDATE users SET password_hash = $1, force_password_change = false WHERE id = $2',
      [newHash, user.id]
    );
    
    // Log the change
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [user.full_name, 'Password Changed', 'Password changed successfully']
    );
    
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Validate token (for session check)
app.get('/api/auth/validate', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ============ TRUNK MOVEMENTS ENDPOINTS ============

// Get all today's movements
app.get('/api/movements', authenticateToken, async (req, res) => {
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
app.get('/api/movements/:id', authenticateToken, async (req, res) => {
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
app.patch('/api/movements/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const userRole = req.user.role;
    const perms = rolePermissions[userRole];
    
    // Check permissions based on what's being updated
    if (updates.status === 'departed' && !perms.canLogDeparture) {
      return res.status(403).json({ error: 'Permission denied: cannot log departures' });
    }
    if (updates.status === 'arrived' && !perms.canLogArrival) {
      return res.status(403).json({ error: 'Permission denied: cannot log arrivals' });
    }
    if (['docked', 'tipping', 'complete'].includes(updates.status) && !perms.canUpdateOps) {
      return res.status(403).json({ error: 'Permission denied: cannot update operations' });
    }
    if (updates.status === 'cancelled' && !perms.canManageTrunks) {
      return res.status(403).json({ error: 'Permission denied: cannot cancel trunks' });
    }
    
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
      [req.user.fullName, `Status: ${movement.status}`, `${movement.trunk_id}: ${movement.origin} → ${movement.destination}`, movement.trunk_id]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update movement error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new trunk movement
app.post('/api/movements', authenticateToken, requirePermission('canManageTrunks'), async (req, res) => {
  try {
    const {
      trunk_id, route_ref, contractor, vehicle_type, origin, destination,
      scheduled_dep, scheduled_arr, direction, status = 'scheduled'
    } = req.body;
    
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
      [req.user.fullName, 'Trunk added', `${trunk_id}: ${origin} → ${destination}`, trunk_id]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Add movement error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ TRUNK SCHEDULE (MASTER) ENDPOINTS ============

// Get all scheduled trunks (master template)
app.get('/api/schedule', authenticateToken, async (req, res) => {
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
app.get('/api/audit', authenticateToken, async (req, res) => {
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

// ============ USER MANAGEMENT ENDPOINTS ============

// Get all users (admin only)
app.get('/api/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, full_name, email, role, location, active, 
              force_password_change, failed_login_attempts, locked_until, last_login, created_at 
       FROM users ORDER BY full_name`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle user active status
app.patch('/api/users/:id/toggle', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    // Prevent disabling own account
    if (parseInt(req.params.id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot disable your own account' });
    }
    
    const result = await pool.query(
      'UPDATE users SET active = NOT active WHERE id = $1 RETURNING id, username, full_name, active',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, user.active ? 'User Enabled' : 'User Disabled', `${user.full_name} (${user.username})`]
    );
    
    // If disabling, also invalidate their sessions
    if (!user.active) {
      await pool.query('DELETE FROM sessions WHERE user_id = $1', [req.params.id]);
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Toggle user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Unlock user account
app.patch('/api/users/:id/unlock', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1 RETURNING id, username, full_name',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'User Unlocked', `${user.full_name} (${user.username})`]
    );
    
    res.json({ message: 'User account unlocked', user: result.rows[0] });
  } catch (err) {
    console.error('Unlock user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Force logout user (admin)
app.post('/api/users/:id/force-logout', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM sessions WHERE user_id = $1', [req.params.id]);
    
    const userResult = await pool.query('SELECT full_name, username FROM users WHERE id = $1', [req.params.id]);
    if (userResult.rows.length > 0) {
      const user = userResult.rows[0];
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        [req.user.fullName, 'Force Logout', `Logged out ${user.full_name} (${user.username})`]
      );
    }
    
    res.json({ message: 'User sessions terminated' });
  } catch (err) {
    console.error('Force logout error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset user password (admin)
app.post('/api/users/:id/reset-password', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { newPassword } = req.body;
    
    // Validate new password
    const errors = validatePassword(newPassword);
    if (errors.length > 0) {
      return res.status(400).json({ error: `Password must contain ${errors.join(', ')}` });
    }
    
    const newHash = await bcrypt.hash(newPassword, 10);
    
    const result = await pool.query(
      'UPDATE users SET password_hash = $1, force_password_change = true, failed_login_attempts = 0, locked_until = NULL WHERE id = $2 RETURNING id, username, full_name',
      [newHash, req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Invalidate all sessions for this user
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [req.params.id]);
    
    const user = result.rows[0];
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'Password Reset', `Reset password for ${user.full_name} (${user.username})`]
    );
    
    res.json({ message: 'Password reset successfully. User must change password on next login.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create user
app.post('/api/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { username, password, full_name, email, role, location } = req.body;
    
    // Validate password
    const errors = validatePassword(password);
    if (errors.length > 0) {
      return res.status(400).json({ error: `Password must contain ${errors.join(', ')}` });
    }
    
    const password_hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, full_name, email, role, location, force_password_change)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING id, username, full_name, email, role, location, active`,
      [username, password_hash, full_name, email, role, location]
    );
    
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'User Created', `Created ${full_name} (${username}) with role ${role}`]
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
    
    // Archive yesterday's movements
    await pool.query(
      `DELETE FROM trunk_movements WHERE movement_date < CURRENT_DATE`
    );
    
    // Check what's already in today's movements (preserve in-transit)
    const existing = await pool.query(
      `SELECT trunk_id FROM trunk_movements WHERE movement_date = CURRENT_DATE`
    );
    const existingIds = existing.rows.map(r => r.trunk_id);
    
    // Copy from schedule to movements for today (only new ones)
    let result;
    if (existingIds.length > 0) {
      result = await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date)
         SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
                scheduled_dep, scheduled_arr, direction, 'scheduled', CURRENT_DATE
         FROM trunk_schedule
         WHERE active = true AND trunk_id NOT IN (SELECT unnest($1::text[]))
         RETURNING trunk_id`,
        [existingIds]
      );
    } else {
      result = await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date)
         SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
                scheduled_dep, scheduled_arr, direction, 'scheduled', CURRENT_DATE
         FROM trunk_schedule
         WHERE active = true
         RETURNING trunk_id`
      );
    }
    
    // Clean up expired sessions
    await pool.query('DELETE FROM sessions WHERE expires_at < NOW()');
    
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

app.get('/api/stats', authenticateToken, async (req, res) => {
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
