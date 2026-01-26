const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const ExcelJS = require('exceljs');
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

// Test database connection and ensure daily_reports table exists
pool.query('SELECT NOW()', async (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected:', res.rows[0].now);
    
    // Auto-create daily_reports table if it doesn't exist
    try {
      await pool.query(`
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
        )
      `);
      console.log('Daily reports table ready');
    } catch (tableErr) {
      console.error('Error creating daily_reports table:', tableErr);
    }
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

// ============ OPERATIONAL DAY HELPER ============
// Operational day runs from 10:30 to 10:30
// A movement at 02:00 on Jan 15 belongs to "Jan 14 night shift"

function getOperationalDay(date = new Date()) {
  const hours = date.getHours();
  const minutes = date.getMinutes();
  
  // If before 10:30, we're still in yesterday's operational day
  if (hours < 10 || (hours === 10 && minutes < 30)) {
    const yesterday = new Date(date);
    yesterday.setDate(yesterday.getDate() - 1);
    return yesterday.toISOString().split('T')[0];
  }
  
  return date.toISOString().split('T')[0];
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
  'viewer': { canView: true, canLogDeparture: false, canLogArrival: false, canUpdateOps: false, canManageTrunks: false, canManageUsers: false, canAmendTrunk: false, canViewPast: false, canViewFuture: false, canCopyDates: false },
  'depot': { canView: true, canLogDeparture: true, canLogArrival: false, canUpdateOps: false, canManageTrunks: false, canManageUsers: false, canAmendTrunk: true, canViewPast: false, canViewFuture: true, canCopyDates: false },
  'gatehouse': { canView: true, canLogDeparture: false, canLogArrival: true, canUpdateOps: false, canManageTrunks: false, canManageUsers: false, canAmendTrunk: false, canViewPast: false, canViewFuture: false, canCopyDates: false },
  'hub-ops': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: false, canAmendTrunk: true, canViewPast: false, canViewFuture: false, canCopyDates: false },
  'supervisor': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: false, canAmendTrunk: true, canViewPast: false, canViewFuture: true, canCopyDates: false },
  'planner': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: false, canAmendTrunk: true, canViewPast: true, canViewFuture: true, canCopyDates: true },
  'admin': { canView: true, canLogDeparture: true, canLogArrival: true, canUpdateOps: true, canManageTrunks: true, canManageUsers: true, canAmendTrunk: true, canViewPast: true, canViewFuture: true, canCopyDates: true }
};

// Date access validation helper
function canAccessDate(userRole, requestedDate) {
  const perms = rolePermissions[userRole];
  if (!perms) return false;
  
  const today = getOperationalDay(new Date());
  const reqDate = requestedDate;
  
  if (reqDate === today) return true; // Everyone can view today
  if (reqDate < today) return perms.canViewPast; // Past dates
  if (reqDate > today) return perms.canViewFuture; // Future dates
  
  return false;
}

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

// Get movements for a specific date (defaults to today's operational day)
// Supports past, present, and future dates based on role permissions
app.get('/api/movements', authenticateToken, async (req, res) => {
  try {
    const today = getOperationalDay(new Date());
    const requestedDate = req.query.date || today;
    
    // Check if user has permission to access this date
    if (!canAccessDate(req.user.role, requestedDate)) {
      return res.status(403).json({ 
        error: 'Permission denied: You do not have access to this date',
        allowedDates: {
          past: rolePermissions[req.user.role].canViewPast,
          today: true,
          future: rolePermissions[req.user.role].canViewFuture
        }
      });
    }
    
    // Simply return whatever movements exist for this date
    // Future dates will be empty until a planner copies/creates them
    // or until the 10:30am reset creates them when that day arrives
    const result = await pool.query(
      `SELECT * FROM trunk_movements 
       WHERE movement_date = $1 
       ORDER BY 
         CASE 
           WHEN scheduled_dep >= '10:30' THEN 0
           ELSE 1
         END,
         scheduled_dep ASC`,
      [requestedDate]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get movements error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Helper function to generate movements for a future date
async function generateMovementsForDate(targetDate) {
  try {
    // Get base schedule
    const schedule = await pool.query(
      'SELECT * FROM trunk_schedule WHERE active = true'
    );
    
    // Get amendments for this date
    const amendments = await pool.query(
      'SELECT * FROM schedule_amendments WHERE amendment_date = $1',
      [targetDate]
    );
    
    const amendmentMap = {};
    amendments.rows.forEach(a => {
      amendmentMap[a.trunk_id] = a;
    });
    
    // Insert movements based on schedule + amendments
    for (const trunk of schedule.rows) {
      const amendment = amendmentMap[trunk.trunk_id];
      
      // Skip if cancelled by amendment
      if (amendment && amendment.amendment_type === 'cancel') {
        continue;
      }
      
      // Use amended values if available, otherwise use schedule values
      const values = amendment && amendment.amendment_type === 'modify' ? {
        trunk_id: trunk.trunk_id,
        route_ref: amendment.new_route_ref || trunk.route_ref,
        contractor: amendment.new_contractor || trunk.contractor,
        vehicle_type: amendment.new_vehicle_type || trunk.vehicle_type,
        origin: amendment.new_origin || trunk.origin,
        destination: amendment.new_destination || trunk.destination,
        scheduled_dep: amendment.new_scheduled_dep || trunk.scheduled_dep,
        scheduled_arr: amendment.new_scheduled_arr || trunk.scheduled_arr,
        direction: amendment.new_direction || trunk.direction,
        is_amendment: true,
        amendment_note: amendment.reason
      } : {
        trunk_id: trunk.trunk_id,
        route_ref: trunk.route_ref,
        contractor: trunk.contractor,
        vehicle_type: trunk.vehicle_type,
        origin: trunk.origin,
        destination: trunk.destination,
        scheduled_dep: trunk.scheduled_dep,
        scheduled_arr: trunk.scheduled_arr,
        direction: trunk.direction,
        is_amendment: false,
        amendment_note: null
      };
      
      await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date, is_amendment, amendment_note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', $10, $11, $12)
         ON CONFLICT DO NOTHING`,
        [values.trunk_id, values.route_ref, values.contractor, values.vehicle_type,
         values.origin, values.destination, values.scheduled_dep, values.scheduled_arr,
         values.direction, targetDate, values.is_amendment, values.amendment_note]
      );
    }
    
    // Add any new trunks from amendments
    for (const amendment of amendments.rows) {
      if (amendment.amendment_type === 'add') {
        await pool.query(
          `INSERT INTO trunk_movements 
           (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
            scheduled_dep, scheduled_arr, direction, status, movement_date, is_amendment, amendment_note)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', $10, true, $11)
           ON CONFLICT DO NOTHING`,
          [amendment.trunk_id, amendment.new_route_ref, amendment.new_contractor,
           amendment.new_vehicle_type, amendment.new_origin, amendment.new_destination,
           amendment.new_scheduled_dep, amendment.new_scheduled_arr, amendment.new_direction,
           targetDate, amendment.reason]
        );
      }
    }
    
    console.log(`Generated movements for ${targetDate}`);
  } catch (err) {
    console.error('Error generating movements:', err);
  }
}

// Get date access permissions for current user
app.get('/api/date-permissions', authenticateToken, (req, res) => {
  const perms = rolePermissions[req.user.role];
  const today = getOperationalDay(new Date());
  
  res.json({
    today: today,
    canViewPast: perms?.canViewPast || false,
    canViewFuture: perms?.canViewFuture || false,
    canCopyDates: perms?.canCopyDates || false,
    role: req.user.role
  });
});

// Get available dates with movement data
app.get('/api/available-dates', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT movement_date FROM trunk_movements 
       ORDER BY movement_date DESC`
    );
    res.json(result.rows.map(r => r.movement_date.toISOString().split('T')[0]));
  } catch (err) {
    console.error('Available dates error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ ROUTE REFERENCE SEARCH ============
// Search for all movements/legs sharing the same route reference
app.get('/api/movements/route/:routeRef', authenticateToken, async (req, res) => {
  try {
    const { routeRef } = req.params;
    const { date } = req.query;
    const targetDate = date || getOperationalDay(new Date());
    
    // Check date access
    if (!canAccessDate(req.user.role, targetDate)) {
      return res.status(403).json({ error: 'Permission denied for this date' });
    }
    
    const result = await pool.query(
      `SELECT * FROM trunk_movements 
       WHERE route_ref = $1 AND movement_date = $2
       ORDER BY scheduled_dep ASC`,
      [routeRef, targetDate]
    );
    
    res.json({
      routeRef: routeRef,
      date: targetDate,
      legCount: result.rows.length,
      legs: result.rows
    });
  } catch (err) {
    console.error('Route reference search error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get unique route references for a given date
app.get('/api/route-refs', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    const targetDate = date || getOperationalDay(new Date());
    
    const result = await pool.query(
      `SELECT DISTINCT route_ref, COUNT(*) as leg_count 
       FROM trunk_movements 
       WHERE movement_date = $1 AND route_ref IS NOT NULL AND route_ref != ''
       GROUP BY route_ref
       HAVING COUNT(*) > 1
       ORDER BY route_ref`,
      [targetDate]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Get route refs error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ COPY HISTORICAL DATE ============
// Copy all movements + amendments from a historical date to a future date
app.post('/api/copy-date', authenticateToken, async (req, res) => {
  try {
    const { sourceDate, targetDate } = req.body;
    const perms = rolePermissions[req.user.role];
    
    // Check permission
    if (!perms.canCopyDates) {
      return res.status(403).json({ error: 'Permission denied: cannot copy dates' });
    }
    
    const today = getOperationalDay(new Date());
    
    // Validate source is in the past
    if (sourceDate >= today) {
      return res.status(400).json({ error: 'Source date must be in the past' });
    }
    
    // Validate target is in the future
    if (targetDate <= today) {
      return res.status(400).json({ error: 'Target date must be in the future' });
    }
    
    // Check if source date has movements
    const sourceMovements = await pool.query(
      'SELECT * FROM trunk_movements WHERE movement_date = $1',
      [sourceDate]
    );
    
    if (sourceMovements.rows.length === 0) {
      return res.status(404).json({ error: 'No movements found for source date' });
    }
    
    // Clear any existing movements for target date
    await pool.query('DELETE FROM trunk_movements WHERE movement_date = $1', [targetDate]);
    
    // Clear any existing amendments for target date
    await pool.query('DELETE FROM schedule_amendments WHERE amendment_date = $1', [targetDate]);
    
    // Copy movements to target date (reset operational fields)
    let copied = 0;
    for (const m of sourceMovements.rows) {
      await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date, is_amendment, amendment_note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'scheduled', $10, $11, $12)`,
        [m.trunk_id, m.route_ref, m.contractor, m.vehicle_type, m.origin, m.destination,
         m.scheduled_dep, m.scheduled_arr, m.direction, targetDate, 
         m.is_amendment, m.amendment_note ? `Copied from ${sourceDate}: ${m.amendment_note}` : `Copied from ${sourceDate}`]
      );
      copied++;
    }
    
    // Log the copy action
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'Date Copy', `Copied ${copied} movements from ${sourceDate} to ${targetDate}`]
    );
    
    res.json({
      message: 'Date copied successfully',
      sourceDate,
      targetDate,
      movementsCopied: copied
    });
  } catch (err) {
    console.error('Copy date error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ SCHEDULE AMENDMENTS ============

// Get amendments for a date
app.get('/api/amendments', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) {
      return res.status(400).json({ error: 'Date parameter required' });
    }
    
    const result = await pool.query(
      'SELECT * FROM schedule_amendments WHERE amendment_date = $1 ORDER BY created_at DESC',
      [date]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Get amendments error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create amendment for a specific date
app.post('/api/amendments', authenticateToken, requirePermission('canAmendTrunk'), async (req, res) => {
  try {
    const { 
      amendment_date, trunk_id, amendment_type, reason,
      new_contractor, new_vehicle_type, new_origin, new_destination,
      new_scheduled_dep, new_scheduled_arr, new_direction, new_route_ref
    } = req.body;
    
    const today = getOperationalDay(new Date());
    
    // Check date access
    if (!canAccessDate(req.user.role, amendment_date)) {
      return res.status(403).json({ error: 'Permission denied for this date' });
    }
    
    // For modifications, get original values
    let originalValues = {};
    if (amendment_type === 'modify' || amendment_type === 'cancel') {
      const original = await pool.query(
        'SELECT * FROM trunk_schedule WHERE trunk_id = $1',
        [trunk_id]
      );
      if (original.rows.length > 0) {
        const o = original.rows[0];
        originalValues = {
          original_contractor: o.contractor,
          original_vehicle_type: o.vehicle_type,
          original_origin: o.origin,
          original_destination: o.destination,
          original_scheduled_dep: o.scheduled_dep,
          original_scheduled_arr: o.scheduled_arr,
          original_direction: o.direction
        };
      }
    }
    
    // Insert or update amendment
    const result = await pool.query(
      `INSERT INTO schedule_amendments 
       (amendment_date, trunk_id, amendment_type, reason, created_by,
        original_contractor, original_vehicle_type, original_origin, original_destination,
        original_scheduled_dep, original_scheduled_arr, original_direction,
        new_contractor, new_vehicle_type, new_origin, new_destination,
        new_scheduled_dep, new_scheduled_arr, new_direction, new_route_ref)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
       ON CONFLICT (amendment_date, trunk_id) 
       DO UPDATE SET 
         amendment_type = EXCLUDED.amendment_type,
         reason = EXCLUDED.reason,
         new_contractor = EXCLUDED.new_contractor,
         new_vehicle_type = EXCLUDED.new_vehicle_type,
         new_origin = EXCLUDED.new_origin,
         new_destination = EXCLUDED.new_destination,
         new_scheduled_dep = EXCLUDED.new_scheduled_dep,
         new_scheduled_arr = EXCLUDED.new_scheduled_arr,
         new_direction = EXCLUDED.new_direction,
         new_route_ref = EXCLUDED.new_route_ref,
         created_at = NOW()
       RETURNING *`,
      [amendment_date, trunk_id, amendment_type, reason, req.user.fullName,
       originalValues.original_contractor, originalValues.original_vehicle_type,
       originalValues.original_origin, originalValues.original_destination,
       originalValues.original_scheduled_dep, originalValues.original_scheduled_arr,
       originalValues.original_direction,
       new_contractor, new_vehicle_type, new_origin, new_destination,
       new_scheduled_dep, new_scheduled_arr, new_direction, new_route_ref]
    );
    
    // If movements already exist for this date, update them
    if (amendment_type === 'modify') {
      await pool.query(
        `UPDATE trunk_movements SET
         contractor = COALESCE($1, contractor),
         vehicle_type = COALESCE($2, vehicle_type),
         origin = COALESCE($3, origin),
         destination = COALESCE($4, destination),
         scheduled_dep = COALESCE($5, scheduled_dep),
         scheduled_arr = COALESCE($6, scheduled_arr),
         direction = COALESCE($7, direction),
         route_ref = COALESCE($8, route_ref),
         is_amendment = true,
         amendment_note = $9,
         updated_at = NOW()
         WHERE trunk_id = $10 AND movement_date = $11`,
        [new_contractor, new_vehicle_type, new_origin, new_destination,
         new_scheduled_dep, new_scheduled_arr, new_direction, new_route_ref,
         reason, trunk_id, amendment_date]
      );
    } else if (amendment_type === 'cancel') {
      await pool.query(
        `UPDATE trunk_movements SET status = 'cancelled', cancel_reason = $1, 
         is_amendment = true, amendment_note = $1, updated_at = NOW()
         WHERE trunk_id = $2 AND movement_date = $3`,
        [reason, trunk_id, amendment_date]
      );
    }
    
    // Log the amendment
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details, trunk_id) VALUES ($1, $2, $3, $4)',
      [req.user.fullName, `Amendment: ${amendment_type}`, `${trunk_id} for ${amendment_date}: ${reason || 'No reason given'}`, trunk_id]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create amendment error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete amendment
app.delete('/api/amendments/:id', authenticateToken, requirePermission('canAmendTrunk'), async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM schedule_amendments WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Amendment not found' });
    }
    
    // Log deletion
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details, trunk_id) VALUES ($1, $2, $3, $4)',
      [req.user.fullName, 'Amendment Deleted', `Removed amendment for ${result.rows[0].amendment_date}`, result.rows[0].trunk_id]
    );
    
    res.json({ message: 'Amendment deleted', amendment: result.rows[0] });
  } catch (err) {
    console.error('Delete amendment error:', err);
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
      'bay', 'seal', 'fill_percent', 'cages', 'cancel_reason',
      'contractor', 'vehicle_type', 'scheduled_dep', 'scheduled_arr'
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

// Get all scheduled trunks (master template - sorted by operational time)
app.get('/api/schedule', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM trunk_schedule WHERE active = true 
       ORDER BY 
         CASE 
           WHEN scheduled_dep >= '10:30' THEN 0
           ELSE 1
         END,
         scheduled_dep ASC`
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

// ============ DAILY RESET ENDPOINT (10:30am - uses Operational Day) ============

// Reset daily movements from schedule (called by cron at 10:30)
// IMPORTANT: If movements already exist for this day (e.g., created by a planner),
// they are preserved and NO new movements are loaded from the master schedule.
app.post('/api/reset-daily', async (req, res) => {
  try {
    const secretKey = req.headers['x-reset-key'];
    if (secretKey !== process.env.RESET_SECRET_KEY) {
      return res.status(403).json({ error: 'Invalid reset key' });
    }
    
    const operationalDay = getOperationalDay();
    const previousDay = new Date();
    previousDay.setDate(previousDay.getDate() - 1);
    const previousDayStr = previousDay.toISOString().split('T')[0];
    
    console.log(`10:30 Reset - New operational day: ${operationalDay}, archiving movements before: ${previousDayStr}`);

    // Archive old movements - mark incomplete ones as cancelled
    await pool.query(
      `UPDATE trunk_movements SET status = 
        CASE WHEN status IN ('scheduled', 'loading') THEN 'cancelled' ELSE status END
       WHERE movement_date < $1 AND status IN ('scheduled', 'loading')`,
      [previousDayStr]
    );
    
    // Check if movements already exist for today (e.g., created by planner)
    const existing = await pool.query(
      `SELECT COUNT(*) as count FROM trunk_movements WHERE movement_date = $1`,
      [operationalDay]
    );
    const existingCount = parseInt(existing.rows[0].count);
    
    let result = { rows: [] };
    
    if (existingCount > 0) {
      // Movements already exist (planner has pre-created them) - DON'T overwrite
      console.log(`Movements already exist for ${operationalDay} (${existingCount} found) - preserving planner's work`);
      
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        ['System', '10:30 Daily Reset', `Preserved ${existingCount} pre-planned movements for ${operationalDay}`]
      );
      
      res.json({ 
        message: `Reset complete. Preserved ${existingCount} pre-planned movements for ${operationalDay}.`,
        operationalDay,
        movementsLoaded: 0,
        existingPreserved: existingCount
      });
    } else {
      // No movements exist - load fresh from master schedule
      result = await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date)
         SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
                scheduled_dep, scheduled_arr, direction, 'scheduled', $1
         FROM trunk_schedule
         WHERE active = true
         RETURNING trunk_id`,
        [operationalDay]
      );
      
      // Log the reset
      await pool.query(
        'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
        ['System', '10:30 Daily Reset', `Loaded ${result.rows.length} movements from master schedule for ${operationalDay}`]
      );
      
      res.json({ 
        message: `Reset complete. Loaded ${result.rows.length} movements for ${operationalDay}.`,
        operationalDay,
        movementsLoaded: result.rows.length,
        existingPreserved: 0
      });
    }
    
    // Clean up expired sessions
    await pool.query('DELETE FROM sessions WHERE expires_at < NOW()');
    
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ 5AM DAILY REPORT GENERATION ============

app.post('/api/generate-daily-report', async (req, res) => {
  try {
    const secretKey = req.headers['x-reset-key'];
    if (secretKey !== process.env.RESET_SECRET_KEY) {
      return res.status(403).json({ error: 'Invalid reset key' });
    }

    const operationalDay = getOperationalDay();
    const reportDate = new Date().toISOString().split('T')[0];
    
    console.log(`Generating 5am daily report for operational day: ${operationalDay}`);

    // Get all movements for current operational day
    const movements = await pool.query(
      `SELECT * FROM trunk_movements WHERE movement_date = $1`,
      [operationalDay]
    );

    const rows = movements.rows;
    
    // Calculate basic counts
    const totalMovements = rows.length;
    const inboundCount = rows.filter(r => r.direction === 'INBOUND').length;
    const outboundCount = rows.filter(r => r.direction === 'OUTBOUND').length;
    const transferCount = rows.filter(r => r.direction === 'TRANSFER').length;

    // Status breakdown
    const completedStatuses = ['complete', 'docked', 'tipping'];
    const inProgressStatuses = ['loading', 'departed', 'in-transit', 'arrived'];
    
    const completedCount = rows.filter(r => completedStatuses.includes(r.status)).length;
    const inProgressCount = rows.filter(r => inProgressStatuses.includes(r.status)).length;
    const scheduledCount = rows.filter(r => r.status === 'scheduled').length;
    const delayedCount = rows.filter(r => r.status === 'delayed').length;
    const cancelledCount = rows.filter(r => r.status === 'cancelled').length;

    // On-time performance calculations
    let onTimeDepartures = 0, lateDepartures = 0, onTimeArrivals = 0, lateArrivals = 0;
    let totalDepVariance = 0, depVarianceCount = 0, totalArrVariance = 0, arrVarianceCount = 0;

    for (const row of rows) {
      if (row.status === 'cancelled') continue;

      // Departure variance
      if (row.actual_dep && row.scheduled_dep) {
        const depVar = calculateVariance(row.actual_dep, row.scheduled_dep);
        if (depVar !== null) {
          totalDepVariance += depVar;
          depVarianceCount++;
          if (depVar <= 15) onTimeDepartures++;
          else lateDepartures++;
        }
      }

      // Arrival variance
      const actualArr = row.gate_arrival || row.dock_time;
      if (actualArr && row.scheduled_arr) {
        const arrVar = calculateVariance(actualArr, row.scheduled_arr);
        if (arrVar !== null) {
          totalArrVariance += arrVar;
          arrVarianceCount++;
          if (arrVar <= 15) onTimeArrivals++;
          else lateArrivals++;
        }
      }
    }

    // Calculate percentages
    const activeMovements = totalMovements - cancelledCount;
    const completionRate = activeMovements > 0 ? Math.round((completedCount / activeMovements) * 10000) / 100 : 0;
    const totalDepartures = onTimeDepartures + lateDepartures;
    const departureOtp = totalDepartures > 0 ? Math.round((onTimeDepartures / totalDepartures) * 10000) / 100 : 0;
    const totalArrivals = onTimeArrivals + lateArrivals;
    const arrivalOtp = totalArrivals > 0 ? Math.round((onTimeArrivals / totalArrivals) * 10000) / 100 : 0;
    const avgDepVariance = depVarianceCount > 0 ? Math.round(totalDepVariance / depVarianceCount) : 0;
    const avgArrVariance = arrVarianceCount > 0 ? Math.round(totalArrVariance / arrVarianceCount) : 0;

    // Hub breakdown
    const hubBreakdown = {};
    const destinations = [...new Set(rows.map(r => r.destination))];
    for (const dest of destinations) {
      const hubRows = rows.filter(r => r.destination === dest && r.status !== 'cancelled');
      const hubCompleted = hubRows.filter(r => completedStatuses.includes(r.status)).length;
      hubBreakdown[dest] = {
        total: hubRows.length,
        completed: hubCompleted,
        inProgress: hubRows.filter(r => inProgressStatuses.includes(r.status)).length,
        delayed: hubRows.filter(r => r.status === 'delayed').length,
        completionRate: hubRows.length > 0 ? Math.round((hubCompleted / hubRows.length) * 100) : 0
      };
    }

    // Contractor breakdown
    const contractorBreakdown = {};
    const contractors = [...new Set(rows.map(r => r.contractor).filter(Boolean))];
    for (const contractor of contractors) {
      const contRows = rows.filter(r => r.contractor === contractor && r.status !== 'cancelled');
      const contCompleted = contRows.filter(r => completedStatuses.includes(r.status)).length;
      contractorBreakdown[contractor] = {
        total: contRows.length,
        completed: contCompleted,
        delayed: contRows.filter(r => r.status === 'delayed').length,
        completionRate: contRows.length > 0 ? Math.round((contCompleted / contRows.length) * 100) : 0
      };
    }

    // Delayed movements details
    const delayedMovements = rows
      .filter(r => r.status === 'delayed')
      .map(r => ({
        trunkId: r.trunk_id,
        routeRef: r.route_ref,
        contractor: r.contractor,
        origin: r.origin,
        destination: r.destination,
        scheduledDep: r.scheduled_dep,
        actualDep: r.actual_dep
      }));

    // Insert or update the report
    await pool.query(`
      INSERT INTO daily_reports (
        report_date, operational_day,
        total_movements, inbound_count, outbound_count, transfer_count,
        completed_count, in_progress_count, scheduled_count, delayed_count, cancelled_count,
        on_time_departures, late_departures, on_time_arrivals, late_arrivals,
        completion_rate, departure_otp, arrival_otp,
        avg_departure_variance, avg_arrival_variance,
        hub_breakdown, contractor_breakdown, delayed_movements
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
      ON CONFLICT (report_date) DO UPDATE SET
        operational_day = EXCLUDED.operational_day,
        total_movements = EXCLUDED.total_movements,
        inbound_count = EXCLUDED.inbound_count,
        outbound_count = EXCLUDED.outbound_count,
        transfer_count = EXCLUDED.transfer_count,
        completed_count = EXCLUDED.completed_count,
        in_progress_count = EXCLUDED.in_progress_count,
        scheduled_count = EXCLUDED.scheduled_count,
        delayed_count = EXCLUDED.delayed_count,
        cancelled_count = EXCLUDED.cancelled_count,
        on_time_departures = EXCLUDED.on_time_departures,
        late_departures = EXCLUDED.late_departures,
        on_time_arrivals = EXCLUDED.on_time_arrivals,
        late_arrivals = EXCLUDED.late_arrivals,
        completion_rate = EXCLUDED.completion_rate,
        departure_otp = EXCLUDED.departure_otp,
        arrival_otp = EXCLUDED.arrival_otp,
        avg_departure_variance = EXCLUDED.avg_departure_variance,
        avg_arrival_variance = EXCLUDED.avg_arrival_variance,
        hub_breakdown = EXCLUDED.hub_breakdown,
        contractor_breakdown = EXCLUDED.contractor_breakdown,
        delayed_movements = EXCLUDED.delayed_movements,
        generated_at = NOW()
    `, [
      reportDate, operationalDay,
      totalMovements, inboundCount, outboundCount, transferCount,
      completedCount, inProgressCount, scheduledCount, delayedCount, cancelledCount,
      onTimeDepartures, lateDepartures, onTimeArrivals, lateArrivals,
      completionRate, departureOtp, arrivalOtp,
      avgDepVariance, avgArrVariance,
      JSON.stringify(hubBreakdown),
      JSON.stringify(contractorBreakdown),
      JSON.stringify(delayedMovements)
    ]);

    // Log the report generation
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', '5am Daily Report', `Generated report for ${operationalDay}: ${completionRate}% complete, ${departureOtp}% OTP departures`]
    );

    res.json({
      message: 'Daily report generated successfully',
      operationalDay,
      summary: {
        totalMovements,
        completionRate: `${completionRate}%`,
        departureOtp: `${departureOtp}%`,
        arrivalOtp: `${arrivalOtp}%`,
        delayed: delayedCount
      }
    });

  } catch (err) {
    console.error('Report generation error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Get daily reports history
app.get('/api/daily-reports', authenticateToken, async (req, res) => {
  try {
    const { days = 7, from, to } = req.query;
    
    let query, params;
    
    if (from && to) {
      query = `SELECT * FROM daily_reports WHERE report_date BETWEEN $1 AND $2 ORDER BY report_date DESC`;
      params = [from, to];
    } else {
      query = `SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT $1`;
      params = [parseInt(days)];
    }
    
    const result = await pool.query(query, params);
    res.json(result.rows);
    
  } catch (err) {
    console.error('Get reports error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single daily report
app.get('/api/daily-reports/:date', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM daily_reports WHERE report_date = $1',
      [req.params.date]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Report not found for this date' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Get report error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Compare two daily reports
app.get('/api/daily-reports/compare/:date1/:date2', authenticateToken, async (req, res) => {
  try {
    const { date1, date2 } = req.params;
    
    const result = await pool.query(
      'SELECT * FROM daily_reports WHERE report_date IN ($1, $2) ORDER BY report_date',
      [date1, date2]
    );
    
    if (result.rows.length < 2) {
      return res.status(404).json({ error: 'One or both reports not found' });
    }
    
    const [report1, report2] = result.rows;
    
    const comparison = {
      dates: { from: report1.report_date, to: report2.report_date },
      report1,
      report2,
      changes: {
        completionRate: {
          from: parseFloat(report1.completion_rate),
          to: parseFloat(report2.completion_rate),
          change: (parseFloat(report2.completion_rate) - parseFloat(report1.completion_rate)).toFixed(2)
        },
        departureOtp: {
          from: parseFloat(report1.departure_otp),
          to: parseFloat(report2.departure_otp),
          change: (parseFloat(report2.departure_otp) - parseFloat(report1.departure_otp)).toFixed(2)
        },
        arrivalOtp: {
          from: parseFloat(report1.arrival_otp),
          to: parseFloat(report2.arrival_otp),
          change: (parseFloat(report2.arrival_otp) - parseFloat(report1.arrival_otp)).toFixed(2)
        },
        delayedCount: {
          from: report1.delayed_count,
          to: report2.delayed_count,
          change: report2.delayed_count - report1.delayed_count
        }
      }
    };
    
    res.json(comparison);
  } catch (err) {
    console.error('Compare reports error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current operational day info
app.get('/api/operational-day', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const operationalDay = getOperationalDay(now);
    
    const opDayDate = new Date(operationalDay + 'T10:30:00');
    const opDayEnd = new Date(opDayDate);
    opDayEnd.setDate(opDayEnd.getDate() + 1);
    
    const msRemaining = opDayEnd - now;
    const hoursRemaining = Math.floor(msRemaining / (1000 * 60 * 60));
    const minsRemaining = Math.floor((msRemaining % (1000 * 60 * 60)) / (1000 * 60));
    
    res.json({
      currentOperationalDay: operationalDay,
      operationalDayStarted: opDayDate.toISOString(),
      operationalDayEnds: opDayEnd.toISOString(),
      currentTime: now.toISOString(),
      nextResetIn: `${hoursRemaining}h ${minsRemaining}m`
    });
  } catch (err) {
    console.error('Operational day error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ STATS ENDPOINT ============

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const operationalDay = getOperationalDay(new Date());
    
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
      WHERE movement_date = $1
    `, [operationalDay]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ METRICS HELPER FUNCTIONS ============

function timeToMinutes(timeStr) {
  if (!timeStr) return null;
  const [hours, mins] = timeStr.split(':').map(Number);
  return hours * 60 + mins;
}

function calculateVariance(actual, scheduled) {
  const actualMins = timeToMinutes(actual);
  const scheduledMins = timeToMinutes(scheduled);
  if (actualMins === null || scheduledMins === null) return null;
  return actualMins - scheduledMins;
}

function calculateMetricsForMovements(movements) {
  const metrics = {
    total: 0,
    departed: 0,
    arrived: 0,
    complete: 0,
    cancelled: 0,
    depOnTime: 0,
    depLate: 0,
    depMinsLost: 0,
    arrOnTime: 0,
    arrLate: 0,
    arrMinsLost: 0,
    totalTurnaround: 0,
    turnaroundCount: 0,
    totalTipDuration: 0,
    tipCount: 0
  };
  
  movements.forEach(m => {
    if (m.status === 'cancelled') {
      metrics.cancelled++;
      return;
    }
    
    metrics.total++;
    
    // Departure metrics
    if (m.actual_dep) {
      metrics.departed++;
      const depVariance = calculateVariance(m.actual_dep, m.scheduled_dep);
      if (depVariance !== null) {
        if (depVariance <= 0) {
          metrics.depOnTime++;
        } else {
          metrics.depLate++;
          metrics.depMinsLost += depVariance;
        }
      }
    }
    
    // Arrival metrics
    if (m.gate_arrival) {
      metrics.arrived++;
      const arrVariance = calculateVariance(m.gate_arrival, m.scheduled_arr);
      if (arrVariance !== null) {
        if (arrVariance <= 0) {
          metrics.arrOnTime++;
        } else {
          metrics.arrLate++;
          metrics.arrMinsLost += arrVariance;
        }
      }
    }
    
    // Turnaround time (gate arrival to tip complete)
    if (m.gate_arrival && m.tip_complete) {
      const turnaround = calculateVariance(m.tip_complete, m.gate_arrival);
      if (turnaround !== null && turnaround > 0) {
        metrics.totalTurnaround += turnaround;
        metrics.turnaroundCount++;
      }
    }
    
    // Tip duration
    if (m.tip_start && m.tip_complete) {
      const tipDuration = calculateVariance(m.tip_complete, m.tip_start);
      if (tipDuration !== null && tipDuration > 0) {
        metrics.totalTipDuration += tipDuration;
        metrics.tipCount++;
      }
    }
    
    if (['docked', 'tipping', 'complete'].includes(m.status)) {
      metrics.complete++;
    }
  });
  
  // Calculate percentages and averages
  metrics.depOnTimePercent = metrics.departed > 0 ? Math.round((metrics.depOnTime / metrics.departed) * 100) : 0;
  metrics.arrOnTimePercent = metrics.arrived > 0 ? Math.round((metrics.arrOnTime / metrics.arrived) * 100) : 0;
  metrics.avgTurnaround = metrics.turnaroundCount > 0 ? Math.round(metrics.totalTurnaround / metrics.turnaroundCount) : 0;
  metrics.avgTipDuration = metrics.tipCount > 0 ? Math.round(metrics.totalTipDuration / metrics.tipCount) : 0;
  
  return metrics;
}

// ============ LIVE METRICS ENDPOINT ============

app.get('/api/metrics/live', authenticateToken, async (req, res) => {
  try {
    const operationalDay = getOperationalDay(new Date());
    
    const result = await pool.query(
      `SELECT * FROM trunk_movements WHERE movement_date = $1`,
      [operationalDay]
    );
    
    const movements = result.rows;
    
    // Network-wide metrics
    const networkMetrics = calculateMetricsForMovements(movements);
    
    // Hub-by-hub metrics
    const hubs = ['NUNEATON HUB 1', 'HUB 2 NUNEATON', 'BRACKNELL HUB', 'BRISTOL HUB', 'HAYDOCK HUB', 'LEEDS HUB'];
    const hubMetrics = {};
    
    hubs.forEach(hub => {
      const hubMovements = movements.filter(m => m.destination === hub);
      hubMetrics[hub] = calculateMetricsForMovements(hubMovements);
    });
    
    res.json({
      date: operationalDay,
      network: networkMetrics,
      hubs: hubMetrics
    });
  } catch (err) {
    console.error('Live metrics error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ HISTORICAL METRICS ENDPOINT ============

app.get('/api/metrics/history', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, hub } = req.query;
    
    let query = `SELECT * FROM trunk_movements WHERE movement_date >= $1 AND movement_date <= $2`;
    const params = [startDate || new Date().toISOString().split('T')[0], endDate || new Date().toISOString().split('T')[0]];
    
    if (hub && hub !== 'all') {
      query += ` AND destination = $3`;
      params.push(hub);
    }
    
    const result = await pool.query(query, params);
    const movements = result.rows;
    
    // Group by date
    const dailyMetrics = {};
    movements.forEach(m => {
      const date = m.movement_date.toISOString().split('T')[0];
      if (!dailyMetrics[date]) {
        dailyMetrics[date] = [];
      }
      dailyMetrics[date].push(m);
    });
    
    // Calculate metrics per day
    const dailySummary = Object.keys(dailyMetrics).sort().map(date => ({
      date,
      ...calculateMetricsForMovements(dailyMetrics[date])
    }));
    
    // Overall period metrics
    const periodMetrics = calculateMetricsForMovements(movements);
    
    res.json({
      startDate: params[0],
      endDate: params[1],
      hub: hub || 'all',
      period: periodMetrics,
      daily: dailySummary
    });
  } catch (err) {
    console.error('History metrics error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ AVAILABLE DATES ENDPOINT ============

app.get('/api/metrics/dates', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT movement_date FROM trunk_movements ORDER BY movement_date DESC LIMIT 90`
    );
    res.json(result.rows.map(r => r.movement_date.toISOString().split('T')[0]));
  } catch (err) {
    console.error('Dates error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ DAILY REPORT EXPORT ENDPOINT ============

app.get('/api/daily-reports/:date/export', authenticateToken, async (req, res) => {
  try {
    const reportDate = req.params.date;
    
    // Get the daily report data
    const reportResult = await pool.query(
      'SELECT * FROM daily_reports WHERE report_date = $1',
      [reportDate]
    );
    
    if (reportResult.rows.length === 0) {
      return res.status(404).json({ error: 'Report not found for this date' });
    }
    
    const report = reportResult.rows[0];
    
    // Get the actual movements for that day
    const movementsResult = await pool.query(
      `SELECT * FROM trunk_movements WHERE movement_date = $1 ORDER BY scheduled_dep`,
      [reportDate]
    );
    const movements = movementsResult.rows;
    
    // Create workbook
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'DX TMS';
    workbook.created = new Date();
    
    // ============ SUMMARY SHEET ============
    const summarySheet = workbook.addWorksheet('Summary');
    
    // Title
    summarySheet.mergeCells('A1:I1');
    summarySheet.getCell('A1').value = 'DX Trunking Daily Report (5am Snapshot)';
    summarySheet.getCell('A1').font = { bold: true, size: 16 };
    summarySheet.getCell('A1').alignment = { horizontal: 'center' };
    
    const reportDateFormatted = new Date(reportDate).toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
    summarySheet.mergeCells('A2:I2');
    summarySheet.getCell('A2').value = `Report Date: ${reportDateFormatted}`;
    summarySheet.getCell('A2').alignment = { horizontal: 'center' };
    
    summarySheet.mergeCells('A3:I3');
    summarySheet.getCell('A3').value = `Generated: ${new Date(report.generated_at).toLocaleString('en-GB')}`;
    summarySheet.getCell('A3').alignment = { horizontal: 'center' };
    summarySheet.getCell('A3').font = { italic: true, size: 10 };
    
    // Network summary
    summarySheet.getCell('A5').value = 'Network Summary';
    summarySheet.getCell('A5').font = { bold: true, size: 14 };
    
    const networkData = [
      ['Total Trunks', report.total_movements],
      ['Inbound', report.inbound_count],
      ['Outbound', report.outbound_count],
      ['Transfer', report.transfer_count],
      ['', ''],
      ['Completed', report.completed_count],
      ['In Progress', report.in_progress_count],
      ['Scheduled', report.scheduled_count],
      ['Delayed', report.delayed_count],
      ['Cancelled', report.cancelled_count],
      ['', ''],
      ['Completion Rate', `${report.completion_rate}%`],
      ['Departure On-Time %', `${report.departure_otp}%`],
      ['On-Time Departures', report.on_time_departures],
      ['Late Departures', report.late_departures],
      ['Arrival On-Time %', `${report.arrival_otp}%`],
      ['On-Time Arrivals', report.on_time_arrivals],
      ['Late Arrivals', report.late_arrivals],
      ['', ''],
      ['Avg Departure Variance (mins)', report.avg_departure_variance],
      ['Avg Arrival Variance (mins)', report.avg_arrival_variance]
    ];
    
    networkData.forEach((row, idx) => {
      summarySheet.getCell(`A${7 + idx}`).value = row[0];
      summarySheet.getCell(`B${7 + idx}`).value = row[1];
      if (row[0] !== '') {
        summarySheet.getCell(`A${7 + idx}`).font = { bold: true };
      }
    });
    
    // Hub breakdown table
    const hubStartRow = 32;
    summarySheet.getCell(`A${hubStartRow}`).value = 'Hub Performance';
    summarySheet.getCell(`A${hubStartRow}`).font = { bold: true, size: 14 };
    
    const hubHeaders = ['Hub', 'Total', 'Completed', 'In Progress', 'Delayed'];
    hubHeaders.forEach((header, idx) => {
      const cell = summarySheet.getCell(hubStartRow + 1, idx + 1);
      cell.value = header;
      cell.font = { bold: true };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
      cell.font = { bold: true, color: { argb: 'FFFFFF' } };
    });
    
    const hubBreakdown = report.hub_breakdown || {};
    Object.entries(hubBreakdown).forEach(([hub, data], idx) => {
      const rowNum = hubStartRow + 2 + idx;
      summarySheet.getCell(rowNum, 1).value = hub;
      summarySheet.getCell(rowNum, 2).value = data.total || 0;
      summarySheet.getCell(rowNum, 3).value = data.completed || 0;
      summarySheet.getCell(rowNum, 4).value = data.inProgress || 0;
      summarySheet.getCell(rowNum, 5).value = data.delayed || 0;
      
      if ((data.delayed || 0) > 0) {
        summarySheet.getCell(rowNum, 5).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FEE2E2' } };
        summarySheet.getCell(rowNum, 5).font = { color: { argb: 'DC2626' } };
      }
    });
    
    // Contractor breakdown table
    const contractorStartRow = hubStartRow + Object.keys(hubBreakdown).length + 5;
    summarySheet.getCell(`A${contractorStartRow}`).value = 'Contractor Performance';
    summarySheet.getCell(`A${contractorStartRow}`).font = { bold: true, size: 14 };
    
    const contractorHeaders = ['Contractor', 'Total', 'Completed', 'Delayed'];
    contractorHeaders.forEach((header, idx) => {
      const cell = summarySheet.getCell(contractorStartRow + 1, idx + 1);
      cell.value = header;
      cell.font = { bold: true };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
      cell.font = { bold: true, color: { argb: 'FFFFFF' } };
    });
    
    const contractorBreakdown = report.contractor_breakdown || {};
    Object.entries(contractorBreakdown).forEach(([contractor, data], idx) => {
      const rowNum = contractorStartRow + 2 + idx;
      summarySheet.getCell(rowNum, 1).value = contractor;
      summarySheet.getCell(rowNum, 2).value = data.total || 0;
      summarySheet.getCell(rowNum, 3).value = data.completed || 0;
      summarySheet.getCell(rowNum, 4).value = data.delayed || 0;
      
      if ((data.delayed || 0) > 0) {
        summarySheet.getCell(rowNum, 4).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FEE2E2' } };
        summarySheet.getCell(rowNum, 4).font = { color: { argb: 'DC2626' } };
      }
    });
    
    // Set column widths
    summarySheet.columns = [
      { width: 25 }, { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 }
    ];
    
    // ============ DETAIL SHEET ============
    const detailSheet = workbook.addWorksheet('Movement Details');
    
    const detailHeaders = [
      'Trunk ID', 'Route Ref', 'Direction', 'Contractor', 'Origin', 'Destination',
      'Sched Dep', 'Actual Dep', 'Dep Variance', 'Sched Arr', 'Gate Arrival', 'Arr Variance',
      'Dock Time', 'Tip Start', 'Tip Complete', 'Status'
    ];
    
    detailHeaders.forEach((header, idx) => {
      const cell = detailSheet.getCell(1, idx + 1);
      cell.value = header;
      cell.font = { bold: true };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
      cell.font = { bold: true, color: { argb: 'FFFFFF' } };
    });
    
    movements.forEach((m, idx) => {
      const rowNum = idx + 2;
      const depVariance = calculateVariance(m.actual_dep, m.scheduled_dep);
      const arrVariance = calculateVariance(m.gate_arrival, m.scheduled_arr);
      
      detailSheet.getCell(rowNum, 1).value = m.trunk_id;
      detailSheet.getCell(rowNum, 2).value = m.route_ref;
      detailSheet.getCell(rowNum, 3).value = m.direction;
      detailSheet.getCell(rowNum, 4).value = m.contractor;
      detailSheet.getCell(rowNum, 5).value = m.origin;
      detailSheet.getCell(rowNum, 6).value = m.destination;
      detailSheet.getCell(rowNum, 7).value = m.scheduled_dep;
      detailSheet.getCell(rowNum, 8).value = m.actual_dep;
      detailSheet.getCell(rowNum, 9).value = depVariance;
      detailSheet.getCell(rowNum, 10).value = m.scheduled_arr;
      detailSheet.getCell(rowNum, 11).value = m.gate_arrival;
      detailSheet.getCell(rowNum, 12).value = arrVariance;
      detailSheet.getCell(rowNum, 13).value = m.dock_time;
      detailSheet.getCell(rowNum, 14).value = m.tip_start;
      detailSheet.getCell(rowNum, 15).value = m.tip_complete;
      detailSheet.getCell(rowNum, 16).value = m.status;
      
      // Color code variances
      if (depVariance !== null) {
        const depCell = detailSheet.getCell(rowNum, 9);
        depCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: depVariance <= 0 ? 'D1FAE5' : 'FEE2E2' } };
      }
      if (arrVariance !== null) {
        const arrCell = detailSheet.getCell(rowNum, 12);
        arrCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: arrVariance <= 0 ? 'D1FAE5' : 'FEE2E2' } };
      }
    });
    
    // Auto-filter
    if (movements.length > 0) {
      detailSheet.autoFilter = {
        from: { row: 1, column: 1 },
        to: { row: movements.length + 1, column: detailHeaders.length }
      };
    }
    
    // Set column widths
    detailSheet.columns = detailHeaders.map(() => ({ width: 12 }));
    detailSheet.getColumn(4).width = 15;
    detailSheet.getColumn(5).width = 15;
    detailSheet.getColumn(6).width = 18;
    
    // ============ DELAYED MOVEMENTS SHEET ============
    const delayedMovements = report.delayed_movements || [];
    if (delayedMovements.length > 0) {
      const delayedSheet = workbook.addWorksheet('Delayed Movements');
      
      const delayedHeaders = ['Trunk ID', 'Route Ref', 'Contractor', 'Origin', 'Destination'];
      delayedHeaders.forEach((header, idx) => {
        const cell = delayedSheet.getCell(1, idx + 1);
        cell.value = header;
        cell.font = { bold: true };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'DC2626' } };
        cell.font = { bold: true, color: { argb: 'FFFFFF' } };
      });
      
      delayedMovements.forEach((d, idx) => {
        const rowNum = idx + 2;
        delayedSheet.getCell(rowNum, 1).value = d.trunkId;
        delayedSheet.getCell(rowNum, 2).value = d.routeRef || '';
        delayedSheet.getCell(rowNum, 3).value = d.contractor || '';
        delayedSheet.getCell(rowNum, 4).value = d.origin;
        delayedSheet.getCell(rowNum, 5).value = d.destination;
      });
      
      delayedSheet.columns = [
        { width: 15 }, { width: 15 }, { width: 18 }, { width: 18 }, { width: 18 }
      ];
    }
    
    // Send file
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=DX_Daily_Report_${reportDate}.xlsx`);
    
    await workbook.xlsx.write(res);
    res.end();
    
    // Log export
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'Daily Report Export', `Exported daily report: ${reportDate}`]
    );
    
  } catch (err) {
    console.error('Daily report export error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ REPORT EXPORT ENDPOINT ============

app.get('/api/report/export', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, hubs } = req.query;
    const hubList = hubs ? hubs.split(',') : null;
    
    let query = `SELECT * FROM trunk_movements WHERE movement_date >= $1 AND movement_date <= $2`;
    const params = [startDate, endDate];
    
    if (hubList && hubList.length > 0 && !hubList.includes('all')) {
      query += ` AND destination = ANY($3)`;
      params.push(hubList);
    }
    
    query += ` ORDER BY movement_date, scheduled_dep`;
    
    const result = await pool.query(query, params);
    const movements = result.rows;
    
    // Create workbook
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'DX TMS';
    workbook.created = new Date();
    
    // ============ SUMMARY SHEET ============
    const summarySheet = workbook.addWorksheet('Summary');
    
    // Title
    summarySheet.mergeCells('A1:I1');
    summarySheet.getCell('A1').value = 'DX Trunking Performance Report';
    summarySheet.getCell('A1').font = { bold: true, size: 16 };
    summarySheet.getCell('A1').alignment = { horizontal: 'center' };
    
    summarySheet.mergeCells('A2:I2');
    summarySheet.getCell('A2').value = `Period: ${startDate} to ${endDate}`;
    summarySheet.getCell('A2').alignment = { horizontal: 'center' };
    
    // Network summary
    const networkMetrics = calculateMetricsForMovements(movements);
    
    summarySheet.getCell('A4').value = 'Network Summary';
    summarySheet.getCell('A4').font = { bold: true, size: 14 };
    
    const networkData = [
      ['Total Trunks', networkMetrics.total],
      ['Departed', networkMetrics.departed],
      ['Arrived', networkMetrics.arrived],
      ['Complete', networkMetrics.complete],
      ['Cancelled', networkMetrics.cancelled],
      ['', ''],
      ['Departure On-Time %', `${networkMetrics.depOnTimePercent}%`],
      ['Departure Minutes Lost', networkMetrics.depMinsLost],
      ['Arrival On-Time %', `${networkMetrics.arrOnTimePercent}%`],
      ['Arrival Minutes Lost', networkMetrics.arrMinsLost],
      ['Avg Turnaround (mins)', networkMetrics.avgTurnaround],
      ['Avg Tip Duration (mins)', networkMetrics.avgTipDuration]
    ];
    
    networkData.forEach((row, idx) => {
      summarySheet.getCell(`A${5 + idx}`).value = row[0];
      summarySheet.getCell(`B${5 + idx}`).value = row[1];
      summarySheet.getCell(`A${5 + idx}`).font = { bold: row[0] !== '' };
    });
    
    // Hub summary table
    const hubStartRow = 20;
    summarySheet.getCell(`A${hubStartRow}`).value = 'Hub Performance';
    summarySheet.getCell(`A${hubStartRow}`).font = { bold: true, size: 14 };
    
    const hubHeaders = ['Hub', 'Total', 'Departed', 'Arrived', 'Complete', 'Dep On-Time %', 'Arr On-Time %', 'Mins Lost (Dep)', 'Mins Lost (Arr)', 'Avg Turnaround'];
    hubHeaders.forEach((header, idx) => {
      const cell = summarySheet.getCell(hubStartRow + 1, idx + 1);
      cell.value = header;
      cell.font = { bold: true };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
      cell.font = { bold: true, color: { argb: 'FFFFFF' } };
    });
    
    const allHubs = ['NUNEATON HUB 1', 'HUB 2 NUNEATON', 'BRACKNELL HUB', 'BRISTOL HUB', 'HAYDOCK HUB', 'LEEDS HUB'];
    const displayHubs = hubList && !hubList.includes('all') ? hubList : allHubs;
    
    displayHubs.forEach((hub, idx) => {
      const hubMovements = movements.filter(m => m.destination === hub);
      const hubM = calculateMetricsForMovements(hubMovements);
      const rowNum = hubStartRow + 2 + idx;
      
      summarySheet.getCell(rowNum, 1).value = hub;
      summarySheet.getCell(rowNum, 2).value = hubM.total;
      summarySheet.getCell(rowNum, 3).value = hubM.departed;
      summarySheet.getCell(rowNum, 4).value = hubM.arrived;
      summarySheet.getCell(rowNum, 5).value = hubM.complete;
      summarySheet.getCell(rowNum, 6).value = `${hubM.depOnTimePercent}%`;
      summarySheet.getCell(rowNum, 7).value = `${hubM.arrOnTimePercent}%`;
      summarySheet.getCell(rowNum, 8).value = hubM.depMinsLost;
      summarySheet.getCell(rowNum, 9).value = hubM.arrMinsLost;
      summarySheet.getCell(rowNum, 10).value = hubM.avgTurnaround;
      
      // Color coding for on-time percentages
      const depCell = summarySheet.getCell(rowNum, 6);
      const arrCell = summarySheet.getCell(rowNum, 7);
      
      [{ cell: depCell, pct: hubM.depOnTimePercent }, { cell: arrCell, pct: hubM.arrOnTimePercent }].forEach(({ cell, pct }) => {
        if (pct >= 95) {
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'D1FAE5' } };
        } else if (pct >= 90) {
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FEF3C7' } };
        } else {
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FEE2E2' } };
        }
      });
    });
    
    // Set column widths
    summarySheet.columns = [
      { width: 20 }, { width: 12 }, { width: 12 }, { width: 12 }, { width: 12 },
      { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 }
    ];
    
    // ============ DETAIL SHEET ============
    const detailSheet = workbook.addWorksheet('Detail');
    
    const detailHeaders = [
      'Date', 'Trunk ID', 'Route Ref', 'Direction', 'Contractor', 'Origin', 'Destination',
      'Sched Dep', 'Actual Dep', 'Dep Variance', 'Sched Arr', 'Gate Arrival', 'Arr Variance',
      'Dock Time', 'Tip Start', 'Tip Complete', 'Tip Duration', 'Turnaround', 'Status'
    ];
    
    detailHeaders.forEach((header, idx) => {
      const cell = detailSheet.getCell(1, idx + 1);
      cell.value = header;
      cell.font = { bold: true };
      cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
      cell.font = { bold: true, color: { argb: 'FFFFFF' } };
    });
    
    movements.forEach((m, idx) => {
      const rowNum = idx + 2;
      const depVariance = calculateVariance(m.actual_dep, m.scheduled_dep);
      const arrVariance = calculateVariance(m.gate_arrival, m.scheduled_arr);
      const tipDuration = calculateVariance(m.tip_complete, m.tip_start);
      const turnaround = calculateVariance(m.tip_complete, m.gate_arrival);
      
      detailSheet.getCell(rowNum, 1).value = m.movement_date.toISOString().split('T')[0];
      detailSheet.getCell(rowNum, 2).value = m.trunk_id;
      detailSheet.getCell(rowNum, 3).value = m.route_ref;
      detailSheet.getCell(rowNum, 4).value = m.direction;
      detailSheet.getCell(rowNum, 5).value = m.contractor;
      detailSheet.getCell(rowNum, 6).value = m.origin;
      detailSheet.getCell(rowNum, 7).value = m.destination;
      detailSheet.getCell(rowNum, 8).value = m.scheduled_dep;
      detailSheet.getCell(rowNum, 9).value = m.actual_dep;
      detailSheet.getCell(rowNum, 10).value = depVariance;
      detailSheet.getCell(rowNum, 11).value = m.scheduled_arr;
      detailSheet.getCell(rowNum, 12).value = m.gate_arrival;
      detailSheet.getCell(rowNum, 13).value = arrVariance;
      detailSheet.getCell(rowNum, 14).value = m.dock_time;
      detailSheet.getCell(rowNum, 15).value = m.tip_start;
      detailSheet.getCell(rowNum, 16).value = m.tip_complete;
      detailSheet.getCell(rowNum, 17).value = tipDuration;
      detailSheet.getCell(rowNum, 18).value = turnaround;
      detailSheet.getCell(rowNum, 19).value = m.status;
      
      // Color code variances
      if (depVariance !== null) {
        const depCell = detailSheet.getCell(rowNum, 10);
        depCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: depVariance <= 0 ? 'D1FAE5' : 'FEE2E2' } };
      }
      if (arrVariance !== null) {
        const arrCell = detailSheet.getCell(rowNum, 13);
        arrCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: arrVariance <= 0 ? 'D1FAE5' : 'FEE2E2' } };
      }
    });
    
    // Auto-filter
    detailSheet.autoFilter = {
      from: { row: 1, column: 1 },
      to: { row: movements.length + 1, column: detailHeaders.length }
    };
    
    // Set column widths
    detailSheet.columns = detailHeaders.map(() => ({ width: 12 }));
    detailSheet.getColumn(5).width = 15;
    detailSheet.getColumn(6).width = 15;
    detailSheet.getColumn(7).width = 18;
    
    // ============ DAILY TRENDS SHEET ============
    if (startDate !== endDate) {
      const trendsSheet = workbook.addWorksheet('Daily Trends');
      
      const trendHeaders = ['Date', 'Total', 'Departed', 'Arrived', 'Complete', 'Dep On-Time %', 'Arr On-Time %', 'Mins Lost'];
      trendHeaders.forEach((header, idx) => {
        const cell = trendsSheet.getCell(1, idx + 1);
        cell.value = header;
        cell.font = { bold: true };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '0099CC' } };
        cell.font = { bold: true, color: { argb: 'FFFFFF' } };
      });
      
      // Group by date
      const dailyData = {};
      movements.forEach(m => {
        const date = m.movement_date.toISOString().split('T')[0];
        if (!dailyData[date]) dailyData[date] = [];
        dailyData[date].push(m);
      });
      
      Object.keys(dailyData).sort().forEach((date, idx) => {
        const dayMetrics = calculateMetricsForMovements(dailyData[date]);
        const rowNum = idx + 2;
        
        trendsSheet.getCell(rowNum, 1).value = date;
        trendsSheet.getCell(rowNum, 2).value = dayMetrics.total;
        trendsSheet.getCell(rowNum, 3).value = dayMetrics.departed;
        trendsSheet.getCell(rowNum, 4).value = dayMetrics.arrived;
        trendsSheet.getCell(rowNum, 5).value = dayMetrics.complete;
        trendsSheet.getCell(rowNum, 6).value = `${dayMetrics.depOnTimePercent}%`;
        trendsSheet.getCell(rowNum, 7).value = `${dayMetrics.arrOnTimePercent}%`;
        trendsSheet.getCell(rowNum, 8).value = dayMetrics.depMinsLost + dayMetrics.arrMinsLost;
      });
      
      trendsSheet.columns = trendHeaders.map(() => ({ width: 15 }));
    }
    
    // Send file
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=TMS_Report_${startDate}_to_${endDate}.xlsx`);
    
    await workbook.xlsx.write(res);
    res.end();
    
    // Log export
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      [req.user.fullName, 'Report Export', `Exported report: ${startDate} to ${endDate}`]
    );
    
  } catch (err) {
    console.error('Report export error:', err);
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
