const { Pool } = require('pg');
const fs = require('fs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function importSchedule() {
  console.log('Importing trunk schedule...');
  
  try {
    // Read the JSON data
    const data = JSON.parse(fs.readFileSync('./trunk-data.json', 'utf8'));
    console.log(`Found ${data.length} trunks to import`);
    
    // Clear existing schedule
    await pool.query('DELETE FROM trunk_schedule');
    console.log('Cleared existing schedule');
    
    // Insert all trunks
    let imported = 0;
    for (const trunk of data) {
      await pool.query(
        `INSERT INTO trunk_schedule 
         (trunk_id, route_ref, contractor, vehicle_type, origin, destination, 
          scheduled_dep, scheduled_arr, direction, active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)`,
        [
          trunk.trunk_id,
          trunk.route_ref,
          trunk.contractor,
          trunk.vehicle_type,
          trunk.origin,
          trunk.destination,
          trunk.scheduled_dep,
          trunk.scheduled_arr,
          trunk.direction
        ]
      );
      imported++;
      if (imported % 50 === 0) {
        console.log(`Imported ${imported} trunks...`);
      }
    }
    
    console.log(`\nSuccessfully imported ${imported} trunks to trunk_schedule`);
    
    // Now load today's movements
    console.log('\nLoading today\'s movements from schedule...');
    
    await pool.query('DELETE FROM trunk_movements WHERE movement_date = CURRENT_DATE');
    
    const result = await pool.query(`
      INSERT INTO trunk_movements 
       (trunk_id, route_ref, contractor, vehicle_type, origin, destination,
        scheduled_dep, scheduled_arr, direction, status, movement_date)
      SELECT trunk_id, route_ref, contractor, vehicle_type, origin, destination,
             scheduled_dep, scheduled_arr, direction, 'scheduled', CURRENT_DATE
      FROM trunk_schedule
      WHERE active = true
      RETURNING trunk_id
    `);
    
    console.log(`Loaded ${result.rows.length} movements for today`);
    
    // Log the import
    await pool.query(
      'INSERT INTO audit_log (user_name, action, details) VALUES ($1, $2, $3)',
      ['System', 'Schedule Import', `Imported ${imported} trunks, loaded ${result.rows.length} movements`]
    );
    
    console.log('\nImport complete!');
    
  } catch (err) {
    console.error('Import error:', err);
  } finally {
    await pool.end();
  }
}

importSchedule();
