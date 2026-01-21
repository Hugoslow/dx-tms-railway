// ============================================================
// NEW ENDPOINTS TO ADD TO YOUR server.js
// ============================================================
// Copy these into your existing server.js file
// Place them after your existing endpoints but before app.listen()
// ============================================================


// ============ HELPER: Calculate Operational Day ============
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


// ============ HELPER: Time variance calculation ============

function timeToMinutes(timeStr) {
  if (!timeStr || timeStr === '') return null;
  const parts = timeStr.split(':');
  if (parts.length !== 2) return null;
  const hours = parseInt(parts[0], 10);
  const mins = parseInt(parts[1], 10);
  if (isNaN(hours) || isNaN(mins)) return null;
  return hours * 60 + mins;
}

function calculateVariance(actual, scheduled) {
  const actualMins = timeToMinutes(actual);
  const scheduledMins = timeToMinutes(scheduled);
  if (actualMins === null || scheduledMins === null) return null;
  
  let variance = actualMins - scheduledMins;
  
  // Handle overnight crossover (e.g., scheduled 23:00, actual 01:00)
  if (variance < -720) variance += 1440; // Add 24 hours
  if (variance > 720) variance -= 1440;  // Subtract 24 hours
  
  return variance;
}


// ============ 5AM DAILY REPORT GENERATION ============

app.post('/api/generate-daily-report', async (req, res) => {
  try {
    const secretKey = req.headers['x-reset-key'];
    if (secretKey !== process.env.RESET_SECRET_KEY) {
      return res.status(403).json({ error: 'Invalid reset key' });
    }

    const operationalDay = getOperationalDay();
    const reportDate = new Date().toISOString().split('T')[0];
    
    console.log(`Generating daily report for operational day: ${operationalDay}`);

    // Get all movements for current operational day
    const movements = await pool.query(`
      SELECT * FROM trunk_movements 
      WHERE movement_date = $1
    `, [operationalDay]);

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
    let onTimeDepartures = 0;
    let lateDepartures = 0;
    let onTimeArrivals = 0;
    let lateArrivals = 0;
    let totalDepVariance = 0;
    let depVarianceCount = 0;
    let totalArrVariance = 0;
    let arrVarianceCount = 0;

    for (const row of rows) {
      if (row.status === 'cancelled') continue;

      // Departure variance
      if (row.actual_dep && row.scheduled_dep) {
        const depVar = calculateVariance(row.actual_dep, row.scheduled_dep);
        if (depVar !== null) {
          totalDepVariance += depVar;
          depVarianceCount++;
          if (depVar <= 15) { // 15 min grace period
            onTimeDepartures++;
          } else {
            lateDepartures++;
          }
        }
      }

      // Arrival variance (using gate_arrival or dock_time)
      const actualArr = row.gate_arrival || row.dock_time;
      if (actualArr && row.scheduled_arr) {
        const arrVar = calculateVariance(actualArr, row.scheduled_arr);
        if (arrVar !== null) {
          totalArrVariance += arrVar;
          arrVarianceCount++;
          if (arrVar <= 15) { // 15 min grace period
            onTimeArrivals++;
          } else {
            lateArrivals++;
          }
        }
      }
    }

    // Calculate percentages
    const activeMovements = totalMovements - cancelledCount;
    const completionRate = activeMovements > 0 
      ? Math.round((completedCount / activeMovements) * 10000) / 100 
      : 0;
    
    const totalDepartures = onTimeDepartures + lateDepartures;
    const departureOtp = totalDepartures > 0 
      ? Math.round((onTimeDepartures / totalDepartures) * 10000) / 100 
      : 0;
    
    const totalArrivals = onTimeArrivals + lateArrivals;
    const arrivalOtp = totalArrivals > 0 
      ? Math.round((onTimeArrivals / totalArrivals) * 10000) / 100 
      : 0;

    const avgDepVariance = depVarianceCount > 0 
      ? Math.round(totalDepVariance / depVarianceCount) 
      : 0;
    const avgArrVariance = arrVarianceCount > 0 
      ? Math.round(totalArrVariance / arrVarianceCount) 
      : 0;

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
        completionRate: hubRows.length > 0 
          ? Math.round((hubCompleted / hubRows.length) * 100) 
          : 0
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
        completionRate: contRows.length > 0 
          ? Math.round((contCompleted / contRows.length) * 100) 
          : 0
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
        actualDep: r.actual_dep,
        scheduledArr: r.scheduled_arr
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


// ============ GET DAILY REPORTS (for viewing history) ============

app.get('/api/daily-reports', authenticateToken, async (req, res) => {
  try {
    const { days = 7, from, to } = req.query;
    
    let query;
    let params;
    
    if (from && to) {
      query = `
        SELECT * FROM daily_reports 
        WHERE report_date BETWEEN $1 AND $2
        ORDER BY report_date DESC
      `;
      params = [from, to];
    } else {
      query = `
        SELECT * FROM daily_reports 
        ORDER BY report_date DESC
        LIMIT $1
      `;
      params = [parseInt(days)];
    }
    
    const result = await pool.query(query, params);
    res.json(result.rows);
    
  } catch (err) {
    console.error('Get reports error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// ============ GET SINGLE DAILY REPORT ============

app.get('/api/daily-reports/:date', authenticateToken, async (req, res) => {
  try {
    const { date } = req.params;
    
    const result = await pool.query(
      'SELECT * FROM daily_reports WHERE report_date = $1',
      [date]
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


// ============ COMPARE REPORTS (day-on-day) ============

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
    
    // Calculate differences
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


// ============ UPDATED DAILY RESET (10:30am) ============
// This replaces your existing /api/reset-daily endpoint

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
    
    console.log(`10:30 Reset - New operational day: ${operationalDay}, archiving: ${previousDayStr}`);

    // Archive movements older than yesterday (keep yesterday for reference)
    await pool.query(
      `DELETE FROM trunk_movements WHERE movement_date < $1`,
      [previousDayStr]
    );
    
    // Check what's already in today's movements 
    // (in case some movements were already added manually)
    const existing = await pool.query(
      `SELECT trunk_id FROM trunk_movements WHERE movement_date = $1`,
      [operationalDay]
    );
    const existingIds = existing.rows.map(r => r.trunk_id);
    
    // Load fresh movements from schedule for the new operational day
    let result;
    if (existingIds.length > 0) {
      result = await pool.query(
        `INSERT INTO trunk_movements 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
          scheduled_dep, scheduled_arr, direction, status, movement_date)
         SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
                scheduled_dep, scheduled_arr, direction, 'scheduled', $1
         FROM trunk_schedule
         WHERE active = true AND trunk_id NOT IN (SELECT unnest($2::text[]))
         RETURNING trunk_id`,
        [operationalDay, existingIds]
      );
    } else {
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
    }
    
    // Clean up expired sessions
    await pool.query('DELETE FROM sessions WHERE expires_at < NOW()');
    
    // Log the reset
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', '10:30 Daily Reset', `Loaded ${result.rows.length} movements for operational day ${operationalDay}`]
    );
    
    res.json({ 
      message: `Reset complete. Loaded ${result.rows.length} movements for ${operationalDay}.`,
      operationalDay,
      movementsLoaded: result.rows.length,
      existingPreserved: existingIds.length
    });
    
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});


// ============ GET CURRENT OPERATIONAL DAY INFO ============

app.get('/api/operational-day', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const operationalDay = getOperationalDay(now);
    
    // Calculate when current operational day started and ends
    const opDayDate = new Date(operationalDay + 'T10:30:00');
    const opDayEnd = new Date(opDayDate);
    opDayEnd.setDate(opDayEnd.getDate() + 1);
    
    res.json({
      currentOperationalDay: operationalDay,
      operationalDayStarted: opDayDate.toISOString(),
      operationalDayEnds: opDayEnd.toISOString(),
      currentTime: now.toISOString(),
      nextResetIn: formatTimeDiff(opDayEnd - now)
    });
    
  } catch (err) {
    console.error('Operational day error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

function formatTimeDiff(ms) {
  const hours = Math.floor(ms / (1000 * 60 * 60));
  const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${minutes}m`;
}
