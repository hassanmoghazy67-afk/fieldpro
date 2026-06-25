require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const path = require('path');
const ws = require('ws');
const multer = require('multer');
// Files land in memory first (not on disk) since we immediately re-upload them
// to Supabase Storage — Railway's filesystem is ephemeral and not meant for
// persistent storage anyway. 10MB cap matches Twilio's MMS size limit, so a
// file too large for MMS gets rejected here rather than failing silently later.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ─── BUSINESS TIMEZONE (Pennsylvania / US Eastern) ─────────────────────────────
// Railway's server clock runs in UTC regardless of where Hassan or the business
// is. These helpers compute "today", date boundaries, and formatted times in
// America/New_York specifically — which automatically handles the EST/EDT
// daylight-saving switch twice a year via the IANA timezone database, no manual
// updates ever needed. This is the single source of truth for "what day/time is
// it for this business" everywhere in the backend.
const BUSINESS_TZ = 'America/New_York';

function nowInBusinessTz() {
  return new Date(new Date().toLocaleString('en-US', { timeZone: BUSINESS_TZ }));
}

// Returns today's date as 'YYYY-MM-DD' in business-local time, not UTC.
function todayInBusinessTz() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  return `${map.year}-${map.month}-${map.day}`;
}

// Converts any Date/timestamp to a 'YYYY-MM-DD' string in business-local time.
function dateInBusinessTz(date) {
  const d = date instanceof Date ? date : new Date(date);
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(d);
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  return `${map.year}-${map.month}-${map.day}`;
}

const app = express();
app.set('trust proxy', 1); // Required for Railway/reverse proxy
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── CRASH RECOVERY ─────────────────────────────────────────────────────────────
// Without these, ANY unhandled error anywhere in the app — a webhook with an
// unexpected payload, a database hiccup, a typo in a rarely-hit code path —
// takes down the entire server process, not just that one request. Railway will
// restart a crashed process automatically, but that still means real downtime
// (missed texts, dropped calls) until it comes back. These two handlers log the
// error and keep the process alive instead. They are a safety net, not a fix for
// the underlying bug — anything caught here should still get investigated.
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION — server stayed up:', err?.message, err?.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION — server stayed up:', reason?.message || reason, reason?.stack);
});

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 500 });
app.use('/api/', limiter);

// Supabase client — ws required for Node < 22
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
  realtime: { transport: ws }
});

// Twilio client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// JWT middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// Checks a granular permission flag on the logged-in user (admins always pass).
// Usage: requirePerm('perm_view_total_revenue')
function requirePerm(flag) {
  return async (req, res, next) => {
    if (req.user.role === 'admin') return next();
    const { data: user } = await supabase.from('users').select(flag).eq('id', req.user.id).single();
    if (!user || user[flag] === false) return res.status(403).json({ error: 'Not permitted' });
    next();
  };
}

// ─── AUTH ────────────────────────────────────────────────────────────────────


// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('count').single();
    if (error) {
      return res.status(503).json({ status: 'error', supabase: 'error: ' + error.message, twilio: process.env.TWILIO_ACCOUNT_SID ? 'configured' : 'missing', jwt: process.env.JWT_SECRET ? 'configured' : 'missing' });
    }
    res.json({
      status: 'ok',
      supabase: 'connected',
      twilio: process.env.TWILIO_ACCOUNT_SID ? 'configured' : 'missing',
      jwt: process.env.JWT_SECRET ? 'configured' : 'missing'
    });
  } catch(e) {
    res.status(503).json({ status: 'error', message: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error) return res.status(500).json({ error: 'Database error: ' + error.message });
    if (!user) return res.status(401).json({ error: 'No account found with that email' });
    if (!user.password_hash) return res.status(401).json({ error: 'This account has no CRM login set up' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
    await supabase.from('users').update({ status: 'online' }).eq('id', user.id);
    const PERM_FIELDS = ['perm_view_jobs','perm_edit_jobs','perm_delete_jobs','perm_view_customers','perm_view_sms','perm_view_booking','perm_view_finance_tools','perm_view_total_revenue','perm_view_reports','perm_view_workflows','perm_view_ai_assistant','perm_view_closing_messages','perm_manage_techs','perm_view_settings'];
    const perms = {}; PERM_FIELDS.forEach(f => perms[f] = user[f] !== false);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, color: user.color, initials: user.initials, ...perms } });
  } catch(e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    await supabase.from('users').update({ status: 'offline' }).eq('id', req.user.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('users').select('id,name,email,role,phone,color,initials,status,is_enabled,legacy_external_id,can_view_all_jobs,can_edit_jobs,can_view_finance,use_masking,direct_phone,default_commission_type,default_commission_value,commission_rules,qualified_job_types,area_restriction_enabled,coverage_zips,coverage_areas,perm_view_jobs,perm_edit_jobs,perm_delete_jobs,perm_view_customers,perm_view_sms,perm_view_booking,perm_view_finance_tools,perm_view_total_revenue,perm_view_reports,perm_view_workflows,perm_view_ai_assistant,perm_view_closing_messages,perm_manage_techs,perm_view_settings,created_at').order('created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/users/:id/permissions', authMiddleware, adminOnly, async (req, res) => {
  try {
  const PERM_FIELDS = ['perm_view_jobs','perm_edit_jobs','perm_delete_jobs','perm_view_customers','perm_view_sms','perm_view_booking','perm_view_finance_tools','perm_view_total_revenue','perm_view_reports','perm_view_workflows','perm_view_ai_assistant','perm_view_closing_messages','perm_manage_techs','perm_view_settings'];
    const update = {};
    PERM_FIELDS.forEach(f => { if (req.body[f] !== undefined) update[f] = !!req.body[f]; });
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id/permissions error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { name, email, password, role, phone, color, default_commission_type, default_commission_value, commission_rules, use_masking, sms_only, legacy_external_id, qualified_job_types } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    // SMS-only techs have no CRM login at all — admin and any tech meant to log in
    // still need a real email + password. This is enforced here in code, not the
    // database, so existing accounts are completely unaffected.
    if (!sms_only && (!email || !password)) return res.status(400).json({ error: 'Email and password required (or mark as SMS-only with no login)' });
    if (sms_only && !phone) return res.status(400).json({ error: 'Phone required for SMS-only techs — that\'s their only way to receive jobs' });
    const hash = password ? await bcrypt.hash(password, 10) : null;
    const initials = name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    const { data, error } = await supabase.from('users').insert({
      name, email: email || null, password_hash: hash, role: role || 'tech', phone, color: color || '#1e6fff', initials,
      default_commission_type: default_commission_type || 'percentage',
      default_commission_value: default_commission_value != null ? parseFloat(default_commission_value) : 30,
      commission_rules: commission_rules || [],
      qualified_job_types: qualified_job_types || [],
      use_masking: use_masking !== undefined ? use_masking : true,
      legacy_external_id: legacy_external_id || null,
      is_enabled: true
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Bulk-import SMS-only techs in one request — used for one-time migrations from
// another dispatch system. Skips any tech whose legacy_external_id already
// exists, so it's safe to re-run without creating duplicates.
app.post('/api/users/bulk-import', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { techs } = req.body;
    if (!Array.isArray(techs) || !techs.length) return res.status(400).json({ error: 'techs array required' });
    const created = [];
    const skipped = [];
    for (const t of techs) {
      if (!t.name || !t.phone) { skipped.push({ ...t, reason: 'missing name or phone' }); continue; }
      if (t.legacy_external_id) {
        const { data: existing } = await supabase.from('users').select('id').eq('legacy_external_id', t.legacy_external_id).single();
        if (existing) { skipped.push({ ...t, reason: 'already imported' }); continue; }
      }
      const initials = t.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
      const { data, error } = await supabase.from('users').insert({
        name: t.name, phone: t.phone, role: 'tech', color: '#1e6fff', initials,
        legacy_external_id: t.legacy_external_id || null, is_enabled: true, use_masking: true,
        default_commission_type: 'percentage', default_commission_value: 30, commission_rules: [], qualified_job_types: []
      }).select().single();
      if (error) skipped.push({ ...t, reason: error.message });
      else created.push(data);
    }
    res.json({ created: created.length, skipped: skipped.length, created_techs: created, skipped_details: skipped });
  } catch(e) {
    console.error('/api/users/bulk-import error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance, default_commission_type, default_commission_value, commission_rules, use_masking, qualified_job_types, is_enabled, area_restriction_enabled, coverage_zips, coverage_areas } = req.body;
    const initials = name ? name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() : undefined;
    const update = { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance, default_commission_type, use_masking };
    if (default_commission_value !== undefined) update.default_commission_value = parseFloat(default_commission_value);
    if (commission_rules !== undefined) update.commission_rules = commission_rules;
    if (qualified_job_types !== undefined) update.qualified_job_types = qualified_job_types;
    if (is_enabled !== undefined) update.is_enabled = is_enabled;
    if (area_restriction_enabled !== undefined) update.area_restriction_enabled = area_restriction_enabled;
    if (coverage_zips !== undefined) update.coverage_zips = coverage_zips;
    if (coverage_areas !== undefined) update.coverage_areas = coverage_areas;
    if (initials) update.initials = initials;
    Object.keys(update).forEach(k => update[k] === undefined && delete update[k]);
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/users/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── CUSTOMERS ───────────────────────────────────────────────────────────────

app.get('/api/customers', authMiddleware, requirePerm('perm_view_customers'), async (req, res) => {
  try {
  const { data, error } = await supabase.from('customers').select('*').order('name');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/customers error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/customers', authMiddleware, async (req, res) => {
  try {
  const { name, phone, email, address, notes } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
    const { data, error } = await supabase.from('customers').insert({ name, phone, email, address, notes }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('new_customer', 'New Customer Added', `${name} was added to customers`);
    res.json(data);
  } catch(e) {
    console.error('/api/customers error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/customers/:id', authMiddleware, async (req, res) => {
  try {
  const { name, phone, email, address, notes } = req.body;
    const { data, error } = await supabase.from('customers').update({ name, phone, email, address, notes }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/customers/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/customers/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { count: jobCount } = await supabase.from('jobs').select('id', { count: 'exact', head: true }).eq('customer_id', req.params.id);
    if (jobCount && jobCount > 0) {
      return res.status(409).json({ error: `Cannot delete — this customer has ${jobCount} job(s) on record. Remove or reassign those jobs first.`, job_count: jobCount });
    }
    const { error } = await supabase.from('customers').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/customers/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── JOBS ─────────────────────────────────────────────────────────────────────

app.get('/api/jobs', authMiddleware, async (req, res) => {
  try {
  let query = supabase.from('jobs').select('*').order('created_at', { ascending: false });
    if (req.user.role === 'tech' && !req.query.all) query = query.eq('tech_id', req.user.id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    const { title, customer_id, customer_name, phone, address, job_type, car_make_model, car_year, tech_id, tech_name, priority, status, notes, job_date, scheduled_date, zip_code, source } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const count = await supabase.from('jobs').select('id', { count: 'exact' });
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const id = `JOB-${num}`;
    const { data, error } = await supabase.from('jobs').insert({
      id, title, customer_id, customer_name, phone, address, job_type, car_make_model, car_year,
      tech_id, tech_name, priority: priority || 'med', status: status || 'new', notes, job_date, scheduled_date,
      zip_code: zip_code || null, source: source || null,
      created_by_user_id: req.user.id, created_by_name: req.user.name
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('job', id, req.user.id, req.user.name, 'created', `Created job for ${customer_name || 'unknown customer'}`);
    await createNotification('new_job', 'New Job Created', `${id} — ${title}`);
    runEventWorkflows('new_job', data).catch(() => {});
    // Auto SMS tech if assigned
    if (tech_id && tech_name) {
      const { data: tech } = await supabase.from('users').select('phone').eq('id', tech_id).single();
      if (tech?.phone) {
        try {
          await twilioClient.messages.create({ body: `FieldPro: You've been assigned ${id} — ${title} at ${address || 'TBD'}. Login to view details.`, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone });
          data.tech_sms_status = 'sent'; data.tech_sms_attempted_at = new Date().toISOString();
          await supabase.from('jobs').update({ tech_sms_status: 'sent', tech_sms_attempted_at: data.tech_sms_attempted_at }).eq('id', id);
        } catch (e) {
          console.log('SMS error:', e.message);
          data.tech_sms_status = 'failed'; data.tech_sms_error = e.message; data.tech_sms_attempted_at = new Date().toISOString();
          await supabase.from('jobs').update({ tech_sms_status: 'failed', tech_sms_error: e.message, tech_sms_attempted_at: data.tech_sms_attempted_at }).eq('id', id);
        }
      }
      await createNotification('job_assigned', 'Job Assigned', `${id} assigned to ${tech_name}`);
      await allocateExtension(id).catch(() => {});
      sendJobAssignmentAudit(data, null).catch(() => {});
      runEventWorkflows('job_assigned', data).catch(() => {});
    }
    res.json(data);
  } catch(e) {
    console.error('/api/jobs POST error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/jobs/:id', authMiddleware, requirePerm('perm_edit_jobs'), async (req, res) => {
  try {
    const { data: old } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    const update = { ...req.body, updated_at: new Date().toISOString() };
    // Mark assignment timestamp + reset confirmation when tech changes. Job-type and
    // area qualification are enforced by only listing the right techs in the dropdown
    // (see /api/jobs/:id/assignable-techs) — not by rejecting the assignment here.
    // This is intentional: the picker should just show the right options, not error.
    if (update.tech_id && update.tech_id !== old?.tech_id) {
      update.assigned_at = new Date().toISOString();
      update.confirmed_by_tech = false;
      update.confirmed_at = null;
    }
    const { data, error } = await supabase.from('jobs').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (update.status && update.status !== old?.status) {
      await logHistory(req.params.id, req.user.id, req.user.name, 'Status changed', 'status', old?.status, update.status);
      await createNotification('job_done', 'Job Completed', req.params.id + ' marked as done');
      runEventWorkflows('status_change', data).catch(() => {});
    }
    if (update.tech_name && update.tech_name !== old?.tech_name) {
      await logHistory(req.params.id, req.user.id, req.user.name, 'Tech assigned', 'tech_name', old?.tech_name, update.tech_name);
      // SMS the tech right away so the no-response timer is meaningful
      if (update.tech_id) {
        const { data: tech } = await supabase.from('users').select('phone').eq('id', update.tech_id).single();
        if (tech?.phone) {
          const msg = await renderTemplate('tpl_job_assigned_tech',
            { job_id: req.params.id, job_type: data.title || data.job_type || '', address: data.address || 'TBD' },
            `FieldPro: You've been assigned {job_id} — {job_type} at {address}. Reply OK to confirm.`);
          try {
            await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone });
            data.tech_sms_status = 'sent'; data.tech_sms_error = null; data.tech_sms_attempted_at = new Date().toISOString();
            await supabase.from('jobs').update({ tech_sms_status: 'sent', tech_sms_error: null, tech_sms_attempted_at: data.tech_sms_attempted_at }).eq('id', req.params.id);
          } catch(e) {
            data.tech_sms_status = 'failed'; data.tech_sms_error = e.message; data.tech_sms_attempted_at = new Date().toISOString();
            await supabase.from('jobs').update({ tech_sms_status: 'failed', tech_sms_error: e.message, tech_sms_attempted_at: data.tech_sms_attempted_at }).eq('id', req.params.id);
          }
        }
      }
      // Audit message to admin: what job, what zip, which tech got it — resends on every reassignment
      // so Hassan can verify dispatch is routing jobs correctly even from Egypt.
      await allocateExtension(req.params.id).catch(() => {});
      sendJobAssignmentAudit(data, old?.tech_name).catch(() => {});
      runEventWorkflows('job_assigned', data).catch(() => {});
    }
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id PUT error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Extracts a US 5-digit zip code from a free-text address. Falls back to the
// job's manually-set zip_code column if parsing fails.
// Appends the required opt-out disclosure to a customer-facing SMS, but only
// the first time we've ever texted that specific number — carriers expect this
// disclosure on initial contact, not repeated on every message. The wording
// invites a reply without actually gating future messages on getting one —
// the system keeps sending normally either way; this is just the framing
// shown to the customer on their first text from us.
async function appendComplianceFooterIfFirstContact(phone, body) {
  try {
    const { data: priorMessages } = await supabase.from('messages').select('id').eq('contact_phone', phone).eq('direction', 'out').limit(1);
    if (priorMessages && priorMessages.length > 0) return body; // not their first text from us — keep it short
    return `${body}\n\nMsg & data rates may apply. Reply SUBSCRIBE to confirm or STOP to unsubscribe.`;
  } catch(e) {
    return `${body}\n\nMsg & data rates may apply. Reply SUBSCRIBE to confirm or STOP to unsubscribe.`;
  }
}

function extractZip(address, fallback) {
  if (!address) return fallback || null;
  const match = address.match(/\b(\d{5})(?:-\d{4})?\b/);
  return match ? match[1] : (fallback || null);
}

// Single source of truth for "can this tech be assigned to this job" — combines
// job-type qualification (Phase: tech qualifications) and area coverage (zips or
// region names). Both checks are opt-in per tech: if a tech has no restrictions
// configured, they're assignable to everything, so nobody is silently locked out
// until an admin actually sets up qualifications/coverage for them.
function isTechAssignableToJob(tech, job) {
  const qualifiedTypes = tech.qualified_job_types || [];
  if (qualifiedTypes.length > 0 && job.job_type && !qualifiedTypes.includes(job.job_type)) return false;

  if (tech.area_restriction_enabled) {
    const zips = tech.coverage_zips || [];
    const areas = (tech.coverage_areas || []).map(a => a.toLowerCase());
    if (zips.length === 0 && areas.length === 0) return false; // restriction on but nothing configured = covers nowhere
    const jobZip = extractZip(job.address, job.zip_code);
    const zipMatch = jobZip && zips.includes(jobZip);
    const addressLower = (job.address || '').toLowerCase();
    const areaMatch = areas.some(a => addressLower.includes(a));
    if (!zipMatch && !areaMatch) return false;
  }
  return true;
}

// Returns only the techs who are actually assignable to a given job — combining
// job-type qualification and area coverage — so the frontend dropdown only ever
// shows the right options instead of erroring after a bad pick.
app.get('/api/jobs/:id/assignable-techs', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('job_type,address,zip_code').eq('id', req.params.id).single();
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech').eq('is_enabled', true);
    const assignable = (techs || []).filter(t => !job || isTechAssignableToJob(t, job));
    res.json(assignable.map(t => ({ id: t.id, name: t.name, color: t.color, initials: t.initials })));
  } catch(e) {
    console.error('/api/jobs/:id/assignable-techs error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Same logic, but for the New Job form before a job exists yet — takes job_type
// and address as query params instead of looking up an existing job.
app.get('/api/techs/assignable', authMiddleware, async (req, res) => {
  try {
  const { job_type, address, zip_code } = req.query;
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech').eq('is_enabled', true);
    const fakeJob = { job_type, address, zip_code };
    const assignable = (techs || []).filter(t => isTechAssignableToJob(t, fakeJob));
    res.json(assignable.map(t => ({ id: t.id, name: t.name, color: t.color, initials: t.initials })));
  } catch(e) {
    console.error('/api/techs/assignable error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

async function sendJobAssignmentAudit(job, previousTechName) {
  const { data: setting } = await supabase.from('settings').select('value').eq('key', 'admin_report_job_assignments').single();
  if (setting?.value === 'false') return;
  const zip = extractZip(job.address, job.zip_code);
  const isReassignment = previousTechName && previousTechName !== job.tech_name;
  const newCount = (job.assignment_audit_count || 0) + 1;
  await supabase.from('jobs').update({ assignment_audit_count: newCount }).eq('id', job.id);
  const lines = [
    isReassignment ? `🔁 Job REASSIGNED — ${job.id}` : `📋 Job assigned — ${job.id}`,
    `Type: ${job.job_type || job.title || '—'}`,
    `Zip: ${zip || '—'}`,
    `Tech: ${job.tech_name || '—'}`
  ];
  if (isReassignment) lines.push(`(was: ${previousTechName})`);
  await sendAdminReport('job_assignment', lines.join('\n'));
}

// ─── EXTENSION / IVR CALLING SYSTEM ─────────────────────────────────────────────
// Each job gets a 3-digit extension ('000'-'999'). A tech calls the fixed business
// number, the IVR asks for the extension, and the system connects them to the
// customer's real number — which the tech never sees directly. Extensions free up
// automatically after inactivity or once the job closes, and get recycled.

// Expires any extension that's been inactive too long, or attached to a closed job,
// freeing the 3-digit code for reuse. Called before allocating a new one and also
// periodically from the alert engine loop.
async function expireStaleExtensions() {
  const settings = await getSettingsMap();
  const inactivityHours = parseFloat(settings.extension_inactivity_hours || '48');
  const cutoff = new Date(Date.now() - inactivityHours * 3600000).toISOString();
  // Free extensions on jobs that are done/cancelled
  await supabase.from('jobs').update({ extension_active: false, call_extension: null })
    .eq('extension_active', true).in('status', ['done', 'cancelled']);
  // Free extensions that haven't been used (or created) recently
  const { data: stale } = await supabase.from('jobs').select('id,extension_created_at,extension_last_used_at')
    .eq('extension_active', true);
  for (const job of stale || []) {
    const lastTouch = job.extension_last_used_at || job.extension_created_at;
    if (lastTouch && new Date(lastTouch) < new Date(cutoff)) {
      await supabase.from('jobs').update({ extension_active: false, call_extension: null }).eq('id', job.id);
    }
  }
}

// Allocates a free 3-digit extension for a job. Reuses any code not currently
// active on another job. Returns the extension string, or null if the pool
// (000-999, minus reserved 000/911-style codes) is somehow exhausted.
async function allocateExtension(jobId) {
  await expireStaleExtensions();
  const { data: existing } = await supabase.from('jobs').select('call_extension').eq('id', jobId).single();
  if (existing?.call_extension) return existing.call_extension; // already has one, reuse it

  const { data: active } = await supabase.from('jobs').select('call_extension').eq('extension_active', true);
  const taken = new Set((active || []).map(j => j.call_extension));
  for (let i = 1; i <= 999; i++) {
    const code = String(i).padStart(3, '0');
    if (!taken.has(code)) {
      await supabase.from('jobs').update({
        call_extension: code, extension_active: true,
        extension_created_at: new Date().toISOString(), extension_last_used_at: new Date().toISOString()
      }).eq('id', jobId);
      return code;
    }
  }
  return null; // pool exhausted — extremely unlikely at this business's scale
}

// ─── CLOSING TICKET SAFETY CHECK ──────────────────────────────────────────────
// Called by the frontend right before a job is closed, to warn if the tech
// closing it isn't the last tech who was actually active in the job's chat thread.
app.get('/api/jobs/:id/close-check', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (!job.last_tech_message_by || !job.tech_name || job.last_tech_message_by === job.tech_name) {
      return res.json({ mismatch: false });
    }
    res.json({
      mismatch: true,
      assigned_tech: job.tech_name,
      last_active_tech: job.last_tech_message_by,
      last_message_at: job.last_tech_message_at
    });
  } catch(e) {
    console.error('/api/jobs/:id/close-check error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/jobs/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const jobId = req.params.id;
    // Several tables reference job_id as a foreign key — clean those up first so
    // the delete doesn't get blocked by a constraint violation. Admin deletion is
    // meant to be unrestricted, so this just clears the path rather than asking
    // the admin to do it manually.
    await supabase.from('ticket_history').delete().eq('job_id', jobId);
    await supabase.from('call_recordings').delete().eq('job_id', jobId);
    await supabase.from('extension_call_log').delete().eq('job_id', jobId);
    await supabase.from('alerts').delete().eq('job_id', jobId);
    await supabase.from('messages').update({ job_id: null }).eq('job_id', jobId); // keep the message, just unlink it
    await supabase.from('bookings').update({ job_id: null }).eq('job_id', jobId); // keep the booking record, unlink it
    await supabase.from('invoices').delete().eq('job_id', jobId);
    const { error } = await supabase.from('jobs').delete().eq('id', jobId);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/jobs/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── INVOICES ─────────────────────────────────────────────────────────────────

app.get('/api/invoices', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('invoices').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/invoices error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/invoices', authMiddleware, async (req, res) => {
  try {
  const { job_id, customer_id, customer_name, tech_id, tech_name, line_items, tax_rate } = req.body;
    const count = await supabase.from('invoices').select('id', { count: 'exact' });
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'invoice_prefix').single();
    const prefix = settings?.value || 'INV';
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const id = `${prefix}-${num}`;
    const subtotal = line_items.reduce((a, i) => a + (i.qty * i.rate), 0);
    const tr = tax_rate || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;
    const { data, error } = await supabase.from('invoices').insert({ id, job_id, customer_id, customer_name, tech_id, tech_name, line_items, subtotal, tax_rate: tr, tax_amount, total, status: 'unpaid' }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (job_id) await supabase.from('jobs').update({ invoice_id: id, status: 'done' }).eq('id', job_id);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/invoices/:id/pay', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('invoices').update({ status: 'paid', paid_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('payment', 'Payment Received', `Invoice ${req.params.id} marked as paid — $${data.total}`);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/pay error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/invoices/:id/send', authMiddleware, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    const { data: customer } = await supabase.from('customers').select('phone,email').eq('id', inv.customer_id).single();
    const { data: bizSettings } = await supabase.from('settings').select('key,value');
    const settings = {};
    bizSettings?.forEach(s => settings[s.key] = s.value);
    const msg = `${settings.business_name || 'FieldPro'} Invoice ${inv.id}\nAmount: $${inv.total?.toFixed(2)}\nStatus: ${inv.status}\n${settings.invoice_footer || 'Thank you for your business!'}`;
    if (customer?.phone) {
      const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
      await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ sent_to_customer: true }).eq('id', req.params.id);
      res.json({ success: true, method: 'sms' });
    } else { res.status(400).json({ error: 'No customer phone on file' }); }
  } catch (e) {
    console.error('/api/invoices/:id/send error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── MESSAGES / SMS ───────────────────────────────────────────────────────────

// Finds the most relevant open job for a phone number, checking both as a
// customer's number and a tech's number — used to auto-link outbound messages
// to a ticket, mirroring the same attribution the inbound webhook already does
// for tech replies. Without this, an outbound message would have no job_id at
// all, making "click the ticket ID from this message" impossible.
async function findRelevantJobForPhone(phone) {
  if (!phone) return null;
  const { data: asCustomerJobs } = await supabase.from('jobs').select('id,assigned_at').eq('phone', phone).in('status', ['new','assigned','in-progress']).order('assigned_at', { ascending: false }).limit(1);
  if (asCustomerJobs?.[0]) return asCustomerJobs[0].id;
  const { data: tech } = await supabase.from('users').select('id').eq('phone', phone).single();
  if (tech) {
    const { data: asTechJobs } = await supabase.from('jobs').select('id,assigned_at').eq('tech_id', tech.id).in('status', ['assigned','in-progress']).order('assigned_at', { ascending: false }).limit(1);
    if (asTechJobs?.[0]) return asTechJobs[0].id;
  }
  return null;
}

app.get('/api/messages', authMiddleware, requirePerm('perm_view_sms'), async (req, res) => {
  try {
  const { data, error } = await supabase.from('messages').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/messages error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/messages/:contact', authMiddleware, async (req, res) => {
  try {
  const contactParam = decodeURIComponent(req.params.contact);
  // Conversations are genuinely identified by phone number, not by name — the
  // same number's stored contact_name can change over time (e.g. before vs
  // after being saved as a customer), so filtering by name alone could split
  // one real conversation across multiple inconsistent buckets. The :contact
  // param may be a phone number (preferred) or, for backward compatibility, a
  // name — we match on phone if it looks like one, otherwise fall back to name.
  const looksLikePhone = /^\+?[\d\s\-\(\)]{7,}$/.test(contactParam);
  let query = supabase.from('messages').select('*').order('created_at');
  query = looksLikePhone ? query.eq('contact_phone', contactParam) : query.eq('contact_name', contactParam);
  const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
  let readQuery = supabase.from('messages').update({ read: true }).eq('direction', 'in');
  readQuery = looksLikePhone ? readQuery.eq('contact_phone', contactParam) : readQuery.eq('contact_name', contactParam);
  await readQuery;
    res.json(data);
  } catch(e) {
    console.error('/api/messages/:contact error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/messages/send', authMiddleware, async (req, res) => {
  const { contact_name, contact_phone, contact_type, body } = req.body;
  if (!contact_phone || !body) return res.status(400).json({ error: 'Phone and message required' });
  try {
    const msg = await twilioClient.messages.create({ body, from: process.env.TWILIO_PHONE_NUMBER, to: contact_phone });
    const job_id = await findRelevantJobForPhone(contact_phone).catch(() => null);
    const { data } = await supabase.from('messages').insert({
      contact_name, contact_phone, contact_type, direction: 'out', body, twilio_sid: msg.sid, read: true, job_id,
      sent_by_user_id: req.user.id, sent_by_name: req.user.name
    }).select().single();
    await logAudit('message', data.id, req.user.id, req.user.name, 'sent', `Sent SMS to ${contact_name || contact_phone}`);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// MMS — accepts an actual uploaded file (image, PDF, etc.) from the browser,
// hosts it on Supabase Storage so it has a real public URL, then hands that
// URL to Twilio as media to attach. Twilio requires a reachable URL for MMS —
// it cannot accept raw file bytes directly, so this upload-then-link step is
// not optional, it's how MMS fundamentally works everywhere, not just here.
app.post('/api/messages/send-mms', authMiddleware, upload.single('file'), async (req, res) => {
  const { contact_name, contact_phone, contact_type, body } = req.body;
  if (!contact_phone) return res.status(400).json({ error: 'Phone required' });
  if (!req.file) return res.status(400).json({ error: 'File required' });
  try {
    const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase();
    const fileName = `mms/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const { error: uploadError } = await supabase.storage.from('message-media').upload(fileName, req.file.buffer, {
      contentType: req.file.mimetype, upsert: false
    });
    if (uploadError) return res.status(500).json({ error: 'Upload failed: ' + uploadError.message });
    const { data: urlData } = supabase.storage.from('message-media').getPublicUrl(fileName);
    const mediaUrl = urlData.publicUrl;

    const msg = await twilioClient.messages.create({
      body: body || '', from: process.env.TWILIO_PHONE_NUMBER, to: contact_phone, mediaUrl: [mediaUrl]
    });
    const job_id = await findRelevantJobForPhone(contact_phone).catch(() => null);
    const { data } = await supabase.from('messages').insert({
      contact_name, contact_phone, contact_type, direction: 'out', body: body || '', twilio_sid: msg.sid, read: true, job_id,
      sent_by_user_id: req.user.id, sent_by_name: req.user.name, media_url: mediaUrl, media_type: req.file.mimetype
    }).select().single();
    await logAudit('message', data.id, req.user.id, req.user.name, 'sent_mms', `Sent MMS to ${contact_name || contact_phone}`);
    res.json(data);
  } catch(e) {
    console.error('/api/messages/send-mms error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Twilio webhook - incoming SMS
const CONFIRM_KEYWORDS = ['ok', 'okay', 'got it', 'gotit', 'confirmed', 'on it', 'onit', 'yes', 'yep', 'k', 'received', 'roger', 'sure', '👍'];
const CLOSING_PATTERN = /\$?\d{2,4}\s*\$?(p|part|parts)?|\d{2,4}\$/i; // matches "150mb", "130$ 20p", "120$", etc.

// Parses a tech's closing message into structured pieces: total, parts cost, tech initials.
// Handles: "130$\n20p", "130\n20$part", "120$\njuan", "150mb" (treated as a flat total).
function parseClosingMessage(body) {
  const lines = body.split('\n').map(l => l.trim()).filter(Boolean);
  let total = null, parts = null, initials = null;
  for (const line of lines) {
    const partsMatch = line.match(/(\d+)\s*\$?\s*(p|part|parts)\b|(\d+)\$\s*(p|part|parts)\b/i);
    const dollarMatch = line.match(/(\d+(?:\.\d+)?)\s*\$|\$\s*(\d+(?:\.\d+)?)/);
    const plainNumberMatch = line.match(/^(\d+(?:\.\d+)?)\s*(mb)?$/i);
    const wordMatch = line.match(/^[a-zA-Z]{2,}$/);
    if (partsMatch) {
      parts = parseFloat(partsMatch[1] || partsMatch[3]);
    } else if (dollarMatch && total === null) {
      total = parseFloat(dollarMatch[1] || dollarMatch[2]);
    } else if (plainNumberMatch && total === null) {
      total = parseFloat(plainNumberMatch[1]);
    } else if (wordMatch && !CONFIRM_KEYWORDS.includes(line.toLowerCase())) {
      initials = line;
    }
  }
  return { total, parts, initials };
}

app.post('/api/webhooks/sms', async (req, res) => {
  try {
    const { From, Body, To } = req.body;
    // Find who sent it
    const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
    const { data: tech } = await supabase.from('users').select('id,name,was_unavailable').eq('phone', From).single();
    const contact_name = customer?.name || tech?.name || From;
    const contact_type = customer ? 'customer' : tech ? 'tech' : 'unknown';
    const bodyTrim = (Body || '').trim();
    const bodyLower = bodyTrim.toLowerCase();

    // Real handling for the SUBSCRIBE keyword invited in the first-contact
    // disclosure message — sends an actual confirmation reply and records the
    // subscription, so the live system genuinely does what the A2P campaign
    // registration claims rather than just mentioning the word in outgoing text.
    if (bodyLower === 'subscribe') {
      if (customer) {
        await supabase.from('customers').update({ sms_subscribed: true, sms_subscribed_at: new Date().toISOString() }).eq('phone', From).catch(() => {});
      }
      await twilioClient.messages.create({
        body: `You're subscribed to SMS updates from Express Lock&Key. Msg & data rates may apply. Reply STOP to unsubscribe at any time.`,
        from: process.env.TWILIO_PHONE_NUMBER, to: From
      });
      await supabase.from('messages').insert({ contact_name, contact_phone: From, contact_type, direction: 'in', body: Body, read: true });
      res.set('Content-Type', 'text/xml');
      return res.send('<Response></Response>');
    }

    let job_id = null;
    let is_closing_attempt = false;
    let closing_amount = null;
    let closing_parts = null;
    let closing_initials = null;

    if (tech) {
      // Tech is active again — mark them available + clear "was unavailable" flag,
      // and surface an alert if they had been unresponsive before
      const wasUnavailable = tech.was_unavailable;
      await supabase.from('users').update({ last_active_at: new Date().toISOString(), was_unavailable: false, status: 'online' }).eq('id', tech.id);

      // Find the most recent job assigned to this tech that hasn't been confirmed/closed,
      // to attribute this message to a job (for chat-tracking + closing detection)
      const { data: openJobs } = await supabase.from('jobs')
        .select('*').eq('tech_id', tech.id).in('status', ['assigned', 'in-progress'])
        .order('assigned_at', { ascending: false }).limit(1);
      const job = openJobs?.[0];

      if (job) {
        job_id = job.id;
        await supabase.from('jobs').update({ last_tech_message_at: new Date().toISOString(), last_tech_message_by: tech.name }).eq('id', job.id);

        // Confirmation keyword check
        if (!job.confirmed_by_tech && CONFIRM_KEYWORDS.some(k => bodyLower === k || bodyLower.startsWith(k + ' ') || bodyLower.includes(k))) {
          await supabase.from('jobs').update({ confirmed_by_tech: true, confirmed_at: new Date().toISOString() }).eq('id', job.id);
        }

        // Closing-message pattern detection (numbers + $ / parts / initials)
        if (CLOSING_PATTERN.test(bodyTrim) && bodyTrim.length < 200) {
          is_closing_attempt = true;
          const parsed = parseClosingMessage(bodyTrim);
          closing_amount = parsed.total;
          closing_parts = parsed.parts;
          closing_initials = parsed.initials;
        }
      }

      if (wasUnavailable) {
        const { data: stillOpen } = await supabase.from('jobs').select('id,title,job_type,status,customer_name,phone,address').eq('tech_id', tech.id).in('status', ['assigned', 'in-progress']);
        await createAlert('tech_available', {
          title: `${tech.name} is now available`,
          body: `${tech.name} is now available. Click to assign a job.${stillOpen?.length ? ` They still have ${stillOpen.length} open job(s) to follow up on.` : ''}`,
          tech_id: tech.id, tech_name: tech.name, severity: 'info',
          data: { open_jobs: stillOpen || [] }
        });
      }
    }

    // Twilio sends incoming MMS media as NumMedia + MediaUrl0/MediaContentType0
    // (indexed 0, 1, 2... for multiple attachments — we store just the first,
    // since the UI shows one attachment per message bubble). Twilio's media
    // URLs require auth to fetch directly, so we re-host on Supabase Storage
    // the same way outbound MMS does, keeping both directions consistent and
    // making the image visible in chat without needing Twilio credentials
    // baked into the frontend.
    let inboundMediaUrl = null, inboundMediaType = null;
    const numMedia = parseInt(req.body.NumMedia || '0');
    if (numMedia > 0 && req.body.MediaUrl0) {
      try {
        const mediaResp = await fetch(req.body.MediaUrl0, {
          headers: { 'Authorization': 'Basic ' + Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64') }
        });
        const mediaBuffer = Buffer.from(await mediaResp.arrayBuffer());
        const contentType = req.body.MediaContentType0 || 'image/jpeg';
        const ext = contentType.split('/')[1] || 'jpg';
        const fileName = `mms/in-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
        const { error: upErr } = await supabase.storage.from('message-media').upload(fileName, mediaBuffer, { contentType, upsert: false });
        if (!upErr) {
          const { data: urlData } = supabase.storage.from('message-media').getPublicUrl(fileName);
          inboundMediaUrl = urlData.publicUrl;
          inboundMediaType = contentType;
        }
      } catch(e) { console.error('Inbound MMS re-host error:', e.message); }
    }

    await supabase.from('messages').insert({ contact_name, contact_phone: From, contact_type, direction: 'in', body: Body, read: false, job_id, is_closing_attempt, closing_amount, closing_parts, closing_initials, media_url: inboundMediaUrl, media_type: inboundMediaType });

    if (is_closing_attempt && tech) {
      await createAlert('closing_message', {
        title: `Closing message from ${tech.name}`,
        body: `${tech.name} sent what looks like a closing/charge message for ${job_id}: "${bodyTrim}"`,
        tech_id: tech.id, tech_name: tech.name, job_id, severity: 'info',
        data: { message: bodyTrim, amount: closing_amount, parts: closing_parts, initials: closing_initials }
      });
    }

    await createNotification('new_message', `New message from ${contact_name}`, Body);
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  } catch(e) {
    console.error('SMS webhook error:', e.message);
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>'); // Twilio just needs a 200 + valid TwiML, even on our internal failure
  }
});

// Masked call - initiate via Twilio
// ─── SETTINGS ─────────────────────────────────────────────────────────────────

app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('settings').select('*');
    if (error) return res.status(500).json({ error: error.message });
    const obj = {};
    data.forEach(s => obj[s.key] = s.value);
    // Always reflect the live Railway env var, not a stale database value —
    // this is the actual source of truth and updates the instant Railway's
    // variable changes, with zero need to manually re-sync a settings row.
    obj.twilio_number = process.env.TWILIO_PHONE_NUMBER || obj.twilio_number || '';
    res.json(obj);
  } catch(e) {
    console.error('/api/settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Public — no auth. Exposes only the Maps key (set in Railway env vars, never the
// database), so both the logged-in CRM and the public booking page can use address
// autocomplete with zero added latency (browser talks to Google directly).
app.get('/api/config/maps-key', (req, res) => {
  res.json({ key: process.env.GOOGLE_MAPS_API_KEY || null });
});

app.get('/api/config/business-info', async (req, res) => {
  try {
    const { data } = await supabase.from('settings').select('key,value').in('key', ['business_name', 'business_phone', 'business_email']);
    const map = {}; data?.forEach(s => map[s.key] = s.value);
    res.json({ name: map.business_name || 'Express Lock&Key', phone: map.business_phone || '', email: map.business_email || '' });
  } catch(e) { res.json({ name: 'Express Lock&Key', phone: '', email: '' }); }
});

app.put('/api/settings', authMiddleware, adminOnly, async (req, res) => {
  try {
  const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await supabase.from('settings').upsert({ key, value, updated_at: new Date().toISOString() });
    }
    res.json({ success: true });
  } catch(e) {
    console.error('/api/settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('notifications').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/notifications error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
  await supabase.from('notifications').update({ read: true }).eq('read', false);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/notifications/read-all error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── REPORTS ──────────────────────────────────────────────────────────────────

app.get('/api/reports/weekly', authMiddleware, requirePerm('perm_view_reports'), async (req, res) => {
  try {
  const offset = parseInt(req.query.offset) || 0;
    const d = nowInBusinessTz();
    d.setDate(d.getDate() + offset * 7);
    const day = d.getDay();
    const mon = new Date(d); mon.setDate(d.getDate() - day + 1);
    const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
    const monStr = dateInBusinessTz(mon);
    const sunStr = dateInBusinessTz(sun);
    let canSeeRevenue = req.user.role === 'admin';
    if (!canSeeRevenue) {
      const { data: u } = await supabase.from('users').select('perm_view_total_revenue').eq('id', req.user.id).single();
      canSeeRevenue = u?.perm_view_total_revenue === true;
    }
    const { data: jobs } = await supabase.from('jobs').select('*').gte('job_date', monStr).lte('job_date', sunStr);
    const { data: invoices } = await supabase.from('invoices').select('*').gte('invoice_date', monStr).lte('invoice_date', sunStr);
    const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech');
    const techStats = techs?.map(t => {
      const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
      const tInv = invoices?.filter(i => i.tech_id === t.id && i.status === 'paid') || [];
      const revenue = tInv.reduce((a, i) => a + (i.total || 0), 0);
      return { tech: t, jobs_assigned: tJobs.length, jobs_completed: tJobs.filter(j => j.status === 'done').length, revenue, completion_rate: tJobs.length ? Math.round(tJobs.filter(j => j.status === 'done').length / tJobs.length * 100) : 0 };
    });
    res.json({
      week_start: monStr, week_end: sunStr, total_jobs: jobs?.length || 0, completed_jobs: jobs?.filter(j => j.status === 'done').length || 0,
      total_revenue: canSeeRevenue ? (invoices?.filter(i => i.status === 'paid').reduce((a, i) => a + (i.total || 0), 0) || 0) : null,
      outstanding: canSeeRevenue ? (invoices?.filter(i => i.status === 'unpaid').reduce((a, i) => a + (i.total || 0), 0) || 0) : null,
      tech_stats: techStats || []
    });
  } catch(e) {
    console.error('/api/reports/weekly error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── CUSTOM COMMISSION REPORT ───────────────────────────────────────────────────
// Shows actual commission paid per tech over a date range, broken down by which
// tier/rule fired on each invoice — since techs can have different rates below
// vs above a job-value threshold. Lets Hassan verify the right rate applied to
// the right jobs, not just see a single blended commission number.
app.get('/api/reports/commission', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { tech_id, start_date, end_date } = req.query;
    let query = supabase.from('invoices').select('*').order('invoice_date', { ascending: false });
    if (tech_id) query = query.eq('tech_id', tech_id);
    if (start_date) query = query.gte('invoice_date', start_date);
    if (end_date) query = query.lte('invoice_date', end_date);
    const { data: invoices, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    const { data: techs } = await supabase.from('users').select('id,name,default_commission_type,default_commission_value,commission_rules').eq('role', 'tech');
    const techMap = {}; (techs || []).forEach(t => techMap[t.id] = t);

    // Group by tech, and within each tech, by which rule tier actually applied
    const byTech = {};
    for (const inv of invoices || []) {
      if (!inv.tech_id) continue;
      const tech = techMap[inv.tech_id];
      const techName = inv.tech_name || tech?.name || 'Unknown';
      if (!byTech[inv.tech_id]) byTech[inv.tech_id] = { tech_id: inv.tech_id, tech_name: techName, tiers: {}, total_commission: 0, total_jobs: 0, total_subtotal: 0 };
      const entry = byTech[inv.tech_id];
      entry.total_jobs++;
      entry.total_commission += inv.tech_commission_amount || 0;
      entry.total_subtotal += inv.subtotal || 0;

      // Identify which tier this invoice fell into, for the breakdown
      const ruleApplied = inv.commission_rule_applied;
      const tierKey = ruleApplied ? `${ruleApplied.operator} $${ruleApplied.amount}` : 'Default rate';
      if (!entry.tiers[tierKey]) entry.tiers[tierKey] = { label: tierKey, rate_type: inv.tech_commission_type, rate_value: inv.tech_commission_value, job_count: 0, commission_total: 0, subtotal_total: 0 };
      entry.tiers[tierKey].job_count++;
      entry.tiers[tierKey].commission_total += inv.tech_commission_amount || 0;
      entry.tiers[tierKey].subtotal_total += inv.subtotal || 0;
    }

    const result = Object.values(byTech).map(entry => ({
      ...entry,
      tiers: Object.values(entry.tiers).sort((a, b) => b.job_count - a.job_count),
      avg_job_value: entry.total_jobs ? Math.round((entry.total_subtotal / entry.total_jobs) * 100) / 100 : 0
    })).sort((a, b) => b.total_commission - a.total_commission);

    res.json({ report: result, total_commission_paid: result.reduce((a, t) => a + t.total_commission, 0) });
  } catch(e) {
    console.error('/api/reports/commission error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/reports/export', authMiddleware, async (req, res) => {
  try {
  const { tech_id, start_date, end_date } = req.query;
    let query = supabase.from('invoices').select('*');
    if (tech_id) query = query.eq('tech_id', tech_id);
    if (start_date) query = query.gte('invoice_date', start_date);
    if (end_date) query = query.lte('invoice_date', end_date);
    const { data: invoices } = await query;
    const csv = ['Invoice #,Job,Customer,Tech,Subtotal,Tax,Total,Status,Date', ...(invoices || []).map(i => `${i.id},${i.job_id || ''},${i.customer_name || ''},${i.tech_name || ''},${i.subtotal || 0},${i.tax_amount || 0},${i.total || 0},${i.status},${i.invoice_date}`)].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=fieldpro-report.csv');
    res.send(csv);
  } catch(e) {
    console.error('/api/reports/export error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Helper
async function createNotification(type, title, body) {
  await supabase.from('notifications').insert({ type, title, body });
}

// ─── ADMIN MULTI-CHANNEL REPORTING ─────────────────────────────────────────────
// Sends Hassan's own operational reports (alert mirrors, job-assignment audits)
// through up to 3 channels: WhatsApp first, SMS fallback if WhatsApp fails,
// and Discord webhook (independent — fires regardless of WhatsApp/SMS outcome,
// since it's free and a good permanent log). Each channel is optional —
// if its setting is blank, it's simply skipped.
async function sendAdminReport(type, message) {
  const { data: s } = await supabase.from('settings').select('key,value');
  const settings = {}; s?.forEach(x => settings[x.key] = x.value);
  const waNumber = settings.admin_report_whatsapp_number;
  const smsNumber = settings.admin_report_sms_number;
  const discordWebhook = settings.admin_report_discord_webhook;

  let whatsappOk = false;
  if (waNumber) {
    try {
      const waFrom = settings.whatsapp_from || 'whatsapp:+14155238886';
      const waTo = waNumber.startsWith('whatsapp:') ? waNumber : `whatsapp:${waNumber}`;
      await twilioClient.messages.create({ body: message, from: waFrom, to: waTo });
      whatsappOk = true;
      await supabase.from('admin_report_log').insert({ type, channel: 'whatsapp', message, status: 'sent' });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'whatsapp', message, status: 'failed', error: e.message });
    }
  }

  if (!whatsappOk && smsNumber) {
    try {
      await twilioClient.messages.create({ body: message, from: process.env.TWILIO_PHONE_NUMBER, to: smsNumber });
      await supabase.from('admin_report_log').insert({ type, channel: 'sms', message, status: 'sent' });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'sms', message, status: 'failed', error: e.message });
    }
  }

  if (discordWebhook) {
    try {
      const r = await fetch(discordWebhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: message }) });
      await supabase.from('admin_report_log').insert({ type, channel: 'discord', message, status: r.ok ? 'sent' : 'failed', error: r.ok ? null : `HTTP ${r.status}` });
    } catch(e) {
      await supabase.from('admin_report_log').insert({ type, channel: 'discord', message, status: 'failed', error: e.message });
    }
  }
}

// ─── ALERT ENGINE ──────────────────────────────────────────────────────────────
// Alerts are a richer cousin of notifications — they carry structured `data`
// (lists of job ids, mismatches, etc.) so the frontend can render an actionable
// popup instead of a plain toast. They're also de-duplicated so we don't spam.

async function getSettingsMap() {
  const { data } = await supabase.from('settings').select('key,value');
  const obj = {}; data?.forEach(s => obj[s.key] = s.value);
  return obj;
}

// ─── MESSAGE TEMPLATES ──────────────────────────────────────────────────────────
// Lets the admin customize the wording of tech reminders, dispatch alerts, and
// customer messages from Settings, without needing a code change. Falls back to
// a sensible default if the template key isn't set. {placeholders} are filled
// from the data object passed in — any key not present is left blank.
async function renderTemplate(templateKey, data, fallback) {
  const settings = await getSettingsMap();
  const template = settings[templateKey] || fallback || '';
  return template.replace(/\{(\w+)\}/g, (_, key) => (data[key] !== undefined && data[key] !== null) ? String(data[key]) : '');
}

// Builds and sends the full appointment reminder "ticket" to the assigned tech,
// respecting the admin's field-visibility checklist (tpl_reminder_fields) and
// custom template (tpl_appointment_reminder_tech). call_extension is a placeholder
// today (admin/dispatch place masked calls from the CRM) — Phase 7 will add a real
// dial-in extension per job so the tech can call the customer directly.
async function sendAppointmentReminderTicket(job) {
  const settings = await getSettingsMap();
  const { data: tech } = await supabase.from('users').select('phone').eq('id', job.tech_id).single();
  if (!tech?.phone) return;
  let fieldVisibility = {};
  try { fieldVisibility = JSON.parse(settings.tpl_reminder_fields || '{}'); } catch(e) {}
  // Make sure this job has an active extension to call the customer through —
  // jobs scheduled long in advance may have had theirs expire by reminder time.
  const ext = fieldVisibility.call_extension !== false ? await allocateExtension(job.id) : null;
  const data = {
    job_id: job.id,
    customer_name: fieldVisibility.customer_name !== false ? job.customer_name : '',
    job_type: fieldVisibility.job_type !== false ? (job.job_type || job.title || '') : '',
    address: fieldVisibility.address !== false ? (job.address || '') : '',
    phone: fieldVisibility.phone === true ? (job.phone || '') : '',
    scheduled_time: fieldVisibility.scheduled_time !== false ? new Date(job.scheduled_date).toLocaleString('en-US', { timeZone: BUSINESS_TZ }) : '',
    notes: fieldVisibility.notes === true ? (job.notes || '') : '',
    call_extension: ext ? `Call ${settings.twilio_number || process.env.TWILIO_PHONE_NUMBER}, enter ext ${ext} to reach customer` : ''
  };
  const fallback = 'APPOINTMENT REMINDER\nJob: {job_id}\nCustomer: {customer_name}\nService: {job_type}\nAddress: {address}\nTime: {scheduled_time}\n{call_extension}';
  const message = await renderTemplate('tpl_appointment_reminder_tech', data, fallback);
  try { await twilioClient.messages.create({ body: message, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone }); } catch(e) { console.log('Reminder SMS error:', e.message); }
}

async function alertsEnabled(settings, key) {
  return settings[key] !== 'false'; // default ON unless explicitly turned off
}

async function createAlert(type, { title, body, job_id = null, tech_id = null, tech_name = null, severity = 'info', data = {}, dedupeWindowMinutes = 30 }) {
  // Avoid duplicate alerts of the same type+job within a window
  if (job_id) {
    const cutoff = new Date(Date.now() - dedupeWindowMinutes * 60000).toISOString();
    const { data: existing } = await supabase.from('alerts').select('id').eq('type', type).eq('job_id', job_id).gte('created_at', cutoff).eq('resolved', false).limit(1);
    if (existing && existing.length) return null;
  }
  const { data: alert } = await supabase.from('alerts').insert({ type, job_id, tech_id, tech_name, title, body, data, severity }).select().single();
  // Mirror into notifications so the existing bell/badge picks it up too
  await createNotification(type, title, body);
  // Mirror to admin's own WhatsApp/SMS/Discord, so Hassan sees what dispatch sees, live.
  const { data: mirrorSetting } = await supabase.from('settings').select('value').eq('key', 'admin_report_mirror_alerts').single();
  if (mirrorSetting?.value !== 'false') {
    sendAdminReport('alert_mirror', `🔔 ${title}\n${body}`).catch(() => {});
  }
  return alert;
}

// Runs all time-based alert checks. Safe to call repeatedly (every few minutes).
async function runAlertChecks() {
  const settings = await getSettingsMap();
  const noRespMin = parseInt(settings.alert_tech_no_response_minutes || '15');
  const staleHours = parseFloat(settings.alert_stale_job_hours || '2');
  const apptHours = parseFloat(settings.alert_appointment_reminder_hours || '1');

  // 1) Tech didn't respond to assigned job within N minutes
  if (await alertsEnabled(settings, 'alert_tech_no_response')) {
    const cutoff = new Date(Date.now() - noRespMin * 60000).toISOString();
    const { data: unconfirmed } = await supabase.from('jobs').select('*')
      .eq('confirmed_by_tech', false).not('tech_id', 'is', null).not('assigned_at', 'is', null)
      .lte('assigned_at', cutoff).in('status', ['assigned']);
    for (const job of unconfirmed || []) {
      const { data: unassigned } = await supabase.from('jobs').select('id,title,job_type,customer_name,phone,address').eq('status', 'new');
      await createAlert('tech_no_response', {
        title: `${job.tech_name} hasn't confirmed ${job.id}`,
        body: `Warning: job ${job.id} assigned to ${job.tech_name} has not been received or confirmed yet.${unassigned?.length ? ` ${unassigned.length} job(s) still unassigned.` : ''}`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'warning',
        data: { unassigned_jobs: unassigned || [] }
      });
      runEventWorkflows('no_response', job).catch(() => {});
    }
  }

  // 2) Stale job — no appointment set & no status change in N hours (recurring until closed/cancelled)
  if (await alertsEnabled(settings, 'alert_stale_job')) {
    const { data: openJobs } = await supabase.from('jobs').select('*').not('status', 'in', '("done","cancelled")');
    const now = Date.now();
    for (const job of openJobs || []) {
      const refTime = job.scheduled_date ? new Date(job.scheduled_date).getTime() : new Date(job.created_at).getTime();
      const hoursSince = (now - refTime) / 3600000;
      if (hoursSince < staleHours) continue;
      const lastAlert = job.last_stale_alert_at ? new Date(job.last_stale_alert_at).getTime() : 0;
      const hoursSinceLastAlert = (now - lastAlert) / 3600000;
      if (hoursSinceLastAlert < staleHours) continue; // only re-fire once per interval
      await createAlert('stale_job', {
        title: `Stale job ${job.id}`,
        body: `Stale job ${job.id} has had no updates for ${staleHours}+ hours.`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'warning',
        dedupeWindowMinutes: 1 // we control re-fire ourselves via last_stale_alert_at
      });
      await supabase.from('jobs').update({ last_stale_alert_at: new Date().toISOString(), stale_alert_count: (job.stale_alert_count || 0) + 1 }).eq('id', job.id);
    }
  }

  // 3) Appointment reminder — N hours before scheduled time, once.
  // Also sends the tech a full reminder "ticket" by SMS, using the customizable
  // template + field checklist from Settings, so they get exactly the info Hassan wants.
  if (await alertsEnabled(settings, 'alert_appointment_reminder')) {
    const now = new Date();
    const windowEnd = new Date(now.getTime() + apptHours * 3600000);
    const { data: upcoming } = await supabase.from('jobs').select('*')
      .eq('appointment_reminder_sent', false).not('scheduled_date', 'is', null)
      .gte('scheduled_date', now.toISOString()).lte('scheduled_date', windowEnd.toISOString())
      .not('status', 'in', '("done","cancelled")');
    for (const job of upcoming || []) {
      await createAlert('appointment_reminder', {
        title: `Upcoming appointment — ${job.id}`,
        body: `Upcoming appointment: ${job.id} is scheduled for ${new Date(job.scheduled_date).toLocaleString('en-US', { timeZone: BUSINESS_TZ })} with ${job.tech_name || 'unassigned tech'}.`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'info'
      });
      if (job.tech_id) await sendAppointmentReminderTicket(job);
      await supabase.from('jobs').update({ appointment_reminder_sent: true }).eq('id', job.id);
    }
  }

  // 5) Recurring workflows — re-fire every interval_minutes for open jobs matching
  // the trigger condition, up to max_repeats, until the job is done/cancelled.
  const { data: recurringWfs } = await supabase.from('workflows').select('*').eq('trigger_type', 'recurring').eq('active', true);
  for (const wf of (recurringWfs || [])) {
    const cond = wf.trigger_condition || {};
    const intervalMin = parseInt(cond.interval_minutes) || 30;
    const maxRepeats = cond.max_repeats != null ? parseInt(cond.max_repeats) : null;
    const last = wf.last_run ? new Date(wf.last_run) : new Date(0);
    if ((Date.now() - last.getTime()) / 60000 < intervalMin) continue;
    if (maxRepeats != null && (wf.run_count || 0) >= maxRepeats) continue;
    const { data: openJobs } = await supabase.from('jobs').select('*').not('status', 'in', '("done","cancelled")');
    let firedAny = false;
    for (const job of openJobs || []) {
      if (!workflowConditionMatches(cond, job)) continue;
      const { data: tech } = job.tech_id ? await supabase.from('users').select('phone').eq('id', job.tech_id).single() : { data: null };
      await executeWorkflowActions(wf.actions, { ...job, tech_phone: tech?.phone || null });
      firedAny = true;
    }
    if (firedAny) await supabase.from('workflows').update({ run_count: (wf.run_count || 0) + 1, last_run: new Date().toISOString() }).eq('id', wf.id);
  }

  // 6) Expire stale call extensions, freeing them for reuse
  await expireStaleExtensions().catch(() => {});

  // 7) Mark techs "unavailable" if no SMS activity in a while, so the next message
  // they send triggers the "now available" alert.
  const inactivityCutoff = new Date(Date.now() - 60 * 60000).toISOString(); // 60 min of silence = unavailable
  await supabase.from('users').update({ was_unavailable: true, status: 'offline' })
    .eq('role', 'tech').eq('was_unavailable', false).lt('last_active_at', inactivityCutoff);
}

// Self-contained interval — no external cron needed. Runs every N minutes (default 5).
let alertIntervalHandle = null;
async function startAlertEngine() {
  const settings = await getSettingsMap();
  const minutes = parseInt(settings.alert_check_interval_minutes || '5');
  if (alertIntervalHandle) clearInterval(alertIntervalHandle);
  alertIntervalHandle = setInterval(() => { runAlertChecks().catch(e => console.error('Alert check error:', e.message)); }, minutes * 60000);
  runAlertChecks().catch(e => console.error('Alert check error:', e.message));
}

// ─── ALERT API ROUTES ──────────────────────────────────────────────────────────

app.get('/api/alerts', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('alerts').select('*').eq('resolved', false).order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/alerts/:id/read', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('alerts').update({ read: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts/:id/read error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/alerts/:id/resolve', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('alerts').update({ resolved: true, read: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/alerts/:id/resolve error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── CLOSING MESSAGES REVIEW PANEL ─────────────────────────────────────────────
// Every tech message flagged as a closing/charge attempt, joined with job context,
// so admin can see at a glance: was it actually closed? on the right tech? what amount?

app.get('/api/closing-messages', authMiddleware, adminOnly, async (req, res) => {
  try {
  const filter = req.query.filter || 'all'; // all, pending, mismatched, closed
    let query = supabase.from('messages').select('*').eq('is_closing_attempt', true).order('created_at', { ascending: false }).limit(100);
    if (filter === 'pending') query = query.eq('closing_reviewed', false);
    const { data: msgs, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Attach job context for each message
    const jobIds = [...new Set((msgs || []).map(m => m.job_id).filter(Boolean))];
    const { data: jobs } = jobIds.length ? await supabase.from('jobs').select('*').in('id', jobIds) : { data: [] };
    const jobsById = {}; (jobs || []).forEach(j => jobsById[j.id] = j);

    const enriched = (msgs || []).map(m => {
      const job = jobsById[m.job_id];
      const mismatched = job && job.last_tech_message_by && job.tech_name && job.last_tech_message_by !== job.tech_name;
      return {
        ...m,
        job_title: job?.title || job?.job_type || null,
        job_status: job?.status || null,
        job_address: job?.address || null,
        assigned_tech: job?.tech_name || null,
        is_closed: job?.status === 'done',
        is_mismatched: !!mismatched,
        invoice_id: job?.invoice_id || null
      };
    });

    const filtered = filter === 'mismatched' ? enriched.filter(m => m.is_mismatched)
      : filter === 'closed' ? enriched.filter(m => m.is_closed)
      : enriched;

    res.json(filtered);
  } catch(e) {
    console.error('/api/closing-messages error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/closing-messages/:id/review', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('messages').update({ closing_reviewed: true }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('closing_message', req.params.id, req.user.id, req.user.name, 'reviewed', `Marked closing message reviewed`);
    res.json(data);
  } catch(e) {
    console.error('/api/closing-messages/:id/review error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/closing-messages/:id/amount', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { amount } = req.body;
    const { data, error } = await supabase.from('messages').update({ closing_amount: amount }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('closing_message', req.params.id, req.user.id, req.user.name, 'amount_corrected', `Corrected closing amount to $${amount}`);
    res.json(data);
  } catch(e) {
    console.error('/api/closing-messages/:id/amount error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/alerts/run-checks', async (req, res) => {
  // Manual/external trigger, mirrors the workflow scheduler pattern already in this app
  const secret = req.headers['x-cron-secret'];
  if (process.env.CRON_SECRET && secret !== process.env.CRON_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try { await runAlertChecks(); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── TICKET HISTORY ───────────────────────────────────────────────────────────

async function logHistory(job_id, user_id, user_name, action, field_changed='', old_value='', new_value='') {
  await supabase.from('ticket_history').insert({ job_id, user_id, user_name, action, field_changed, old_value, new_value });
}

// General-purpose "who did what" log — covers entities ticket_history can't
// (messages, invoices, closing message reviews), since those aren't always
// tied to a single job_id the way ticket history is. Failures here are
// deliberately swallowed (.catch) since a logging failure should never block
// the actual action the user is trying to take.
async function logAudit(entityType, entityId, userId, userName, action, details = '') {
  try {
    await supabase.from('audit_log').insert({ entity_type: entityType, entity_id: entityId, user_id: userId, user_name: userName, action, details });
  } catch(e) { console.error('logAudit error:', e.message); }
}

// ─── COMMISSION RESOLVER ───────────────────────────────────────────────────────
// Given a tech and an invoice subtotal, figures out which commission to apply.
// Checks conditional rules first (in order, first match wins), falls back to the
// tech's default rate if no rule matches or none are configured.
function resolveCommission(tech, subtotal) {
  const rules = tech?.commission_rules || [];
  for (const rule of rules) {
    const amt = parseFloat(rule.amount);
    let matches = false;
    if (rule.operator === 'below' && subtotal < amt) matches = true;
    else if (rule.operator === 'at_or_above' && subtotal >= amt) matches = true;
    else if (rule.operator === 'above' && subtotal > amt) matches = true;
    else if (rule.operator === 'at_or_below' && subtotal <= amt) matches = true;
    if (matches) {
      return { type: rule.type, value: parseFloat(rule.value), rule_applied: rule };
    }
  }
  return { type: tech?.default_commission_type || 'percentage', value: parseFloat(tech?.default_commission_value) || 0, rule_applied: null };
}

function calcCommissionAmount(type, value, subtotal) {
  return type === 'percentage' ? subtotal * (value / 100) : value;
}

// Generates (or reuses) an unguessable token for an invoice's public receipt page.
const crypto = require('crypto');
async function ensureReceiptToken(invoiceId) {
  const { data: inv } = await supabase.from('invoices').select('receipt_token').eq('id', invoiceId).single();
  if (inv?.receipt_token) return inv.receipt_token;
  const token = crypto.randomBytes(16).toString('hex');
  await supabase.from('invoices').update({ receipt_token: token }).eq('id', invoiceId);
  return token;
}

// Lets the frontend preview which commission would apply before creating the invoice
app.get('/api/techs/:id/commission-preview', authMiddleware, async (req, res) => {
  try {
  const subtotal = parseFloat(req.query.subtotal) || 0;
    const { data: tech } = await supabase.from('users').select('*').eq('id', req.params.id).single();
    if (!tech) return res.status(404).json({ error: 'Tech not found' });
    const resolved = resolveCommission(tech, subtotal);
    res.json({
      type: resolved.type, value: resolved.value,
      amount: calcCommissionAmount(resolved.type, resolved.value, subtotal),
      rule_applied: resolved.rule_applied
    });
  } catch(e) {
    console.error('/api/techs/:id/commission-preview error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/jobs/:id/history', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('ticket_history').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/history error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// General audit log — admin only. Optional entity_type + entity_id filters let
// the frontend pull "everything that happened to this invoice" or "everything
// that happened to this job" without exposing the whole log to non-admins.
app.get('/api/audit-log', authMiddleware, adminOnly, async (req, res) => {
  try {
    let query = supabase.from('audit_log').select('*').order('created_at', { ascending: false }).limit(200);
    if (req.query.entity_type) query = query.eq('entity_type', req.query.entity_type);
    if (req.query.entity_id) query = query.eq('entity_id', req.query.entity_id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/audit-log error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Admin can freely correct or remove history entries — e.g. fixing a mistaken log
// line. No extra checks beyond admin-only, by design.
app.put('/api/ticket-history/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { action, new_value } = req.body;
    const update = {};
    if (action !== undefined) update.action = action;
    if (new_value !== undefined) update.new_value = new_value;
    const { data, error } = await supabase.from('ticket_history').update(update).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/ticket-history/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/ticket-history/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { error } = await supabase.from('ticket_history').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/ticket-history/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── EXTENSION MANAGEMENT (manual, from the ticket UI) ─────────────────────────
app.get('/api/jobs/:id/extension', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('call_extension,extension_active,extension_created_at,extension_last_used_at').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json(job);
  } catch(e) {
    console.error('/api/jobs/:id/extension error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/jobs/:id/extension/renew', authMiddleware, async (req, res) => {
  try {
  const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    // Renewing just bumps last_used_at so it survives the inactivity window — keeps the same code.
    if (job.call_extension && job.extension_active) {
      await supabase.from('jobs').update({ extension_last_used_at: new Date().toISOString() }).eq('id', req.params.id);
      return res.json({ extension: job.call_extension, renewed: true });
    }
    const ext = await allocateExtension(req.params.id);
    res.json({ extension: ext, renewed: false, newly_created: true });
  } catch(e) {
    console.error('/api/jobs/:id/extension/renew error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/jobs/:id/extension/free', authMiddleware, adminOnly, async (req, res) => {
  try {
  await supabase.from('jobs').update({ extension_active: false, call_extension: null }).eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/jobs/:id/extension/free error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/extensions/active', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('jobs').select('id,call_extension,tech_name,customer_name,extension_last_used_at,status').eq('extension_active', true).order('call_extension');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/extensions/active error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── TAGS ────────────────────────────────────────────────────────────────────

app.get('/api/tags', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('tags').select('*').order('label');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/tags', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { label, color } = req.body;
    if (!label) return res.status(400).json({ error: 'Label required' });
    const { data, error } = await supabase.from('tags').insert({ label, color: color || '#1e6fff' }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/tags/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { error } = await supabase.from('tags').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch(e) {
    console.error('/api/tags/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/jobs/:id/tags', authMiddleware, async (req, res) => {
  try {
  const { tags } = req.body;
    const { data: old } = await supabase.from('jobs').select('tags').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('jobs').update({ tags, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logHistory(req.params.id, req.user.id, req.user.name, 'Tags updated', 'tags', JSON.stringify(old?.tags), JSON.stringify(tags));
    const newTags = (tags || []).filter(t => !(old?.tags || []).includes(t));
    if (newTags.length) runEventWorkflows('tag_added', data).catch(() => {});
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/tags error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── CALL RECORDINGS ──────────────────────────────────────────────────────────

app.get('/api/jobs/:id/recordings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('call_recordings').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/recordings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Twilio recording callback
app.post('/api/webhooks/recording', async (req, res) => {
  try {
    const { CallSid, RecordingSid, RecordingUrl, RecordingDuration, To, From } = req.body;
    const { data: customer } = await supabase.from('customers').select('name').eq('phone', To).single();
    const { data: tech } = await supabase.from('users').select('name').eq('phone', From).single();
    // Try to find associated job
    const { data: jobs } = await supabase.from('jobs').select('id').or(`customer_name.eq.${customer?.name || ''},tech_name.eq.${tech?.name || ''}`).eq('status', 'in-progress').limit(1);
    const job_id = jobs?.[0]?.id || null;
    await supabase.from('call_recordings').insert({
      job_id, tech_name: tech?.name || From, customer_name: customer?.name || To,
      call_sid: CallSid, recording_sid: RecordingSid,
      recording_url: RecordingUrl ? RecordingUrl + '.mp3' : null,
      duration: parseInt(RecordingDuration) || 0
    });
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  } catch(e) {
    console.error('Recording webhook error:', e.message);
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  }
});

// Update masked call to include recording
// ─── INVOICE WITH COMMISSION ──────────────────────────────────────────────────

app.post('/api/invoices/advanced', authMiddleware, async (req, res) => {
  try {
  const { job_id, customer_id, customer_name, tech_id, tech_name, line_items, parts_items, tax_rate, tech_commission_type, tech_commission_value, use_auto_commission } = req.body;
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'invoice_prefix').single();
    const prefix = settings?.value || 'INV';
    const count = await supabase.from('invoices').select('id', { count: 'exact' });
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const id = `${prefix}-${num}`;
    const all_items = [...(line_items || []), ...(parts_items || [])];
    const labor_cost = (line_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const parts_cost = (parts_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const subtotal = labor_cost + parts_cost;
    const tr = parseFloat(tax_rate) || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;

    let commType = tech_commission_type, commValue = parseFloat(tech_commission_value), ruleApplied = null;
    if (use_auto_commission && tech_id) {
      const { data: tech } = await supabase.from('users').select('*').eq('id', tech_id).single();
      if (tech) {
        const resolved = resolveCommission(tech, subtotal);
        commType = resolved.type; commValue = resolved.value; ruleApplied = resolved.rule_applied;
      }
    }
    const tech_commission_amount = calcCommissionAmount(commType, commValue, subtotal);

    const { data, error } = await supabase.from('invoices').insert({
      id, job_id, customer_id, customer_name, tech_id, tech_name,
      line_items: all_items, subtotal, tax_rate: tr, tax_amount, total, status: 'unpaid',
      parts_cost, labor_cost, tech_commission_type: commType, tech_commission_value: commValue,
      tech_commission_amount, commission_rule_applied: ruleApplied
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    if (job_id) {
      await supabase.from('jobs').update({ invoice_id: id, status: 'done', close_date: new Date().toISOString() }).eq('id', job_id);
      await logHistory(job_id, req.user.id, req.user.name, 'Invoice created', 'invoice_id', '', id);
    }
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/advanced error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Send receipt
app.post('/api/invoices/:id/receipt', authMiddleware, async (req, res) => {
  try {
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    const { data: customer } = await supabase.from('customers').select('phone').eq('id', inv.customer_id).single();
    const { data: bizSettings } = await supabase.from('settings').select('key,value');
    const s = {}; bizSettings?.forEach(x => s[x.key] = x.value);
    const token = await ensureReceiptToken(inv.id);
    const link = `${req.protocol}://${req.get('host')}/receipt/${token}`;
    const msg = `Hi! Here's your receipt from ${s.business_name || 'Express Lock&Key'}: ${link}`;
    if (customer?.phone) {
      const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
      await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ receipt_sent: true }).eq('id', req.params.id);
      if (inv.job_id) await logHistory(inv.job_id, req.user.id, req.user.name, 'Receipt sent', 'receipt', '', customer.phone);
      res.json({ success: true, link });
    } else { res.status(400).json({ error: 'No phone on file' }); }
  } catch(e) {
    console.error('/api/invoices/:id/receipt error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Serve frontend
// ─── RESERVE WITH GOOGLE BOOKINGS ──────────────────────────────────────────────
// NOT YET CONNECTED to Google's real Reservations integration — that requires
// Partner Portal approval and Google's exact CreateBooking/CheckAvailability
// protocol (gRPC or REST, with mutual TLS + HTTP Basic Auth credentials Google
// issues after approval). This endpoint is a structural placeholder shaped like
// Google's real booking payload, so once approved, only the auth layer and field
// mapping need to change — not the underlying CRM plumbing.
app.post('/api/google-reserve/booking', async (req, res) => {
  try {
    const { data: setting } = await supabase.from('settings').select('value').eq('key', 'google_reserve_connected').single();
    if (setting?.value !== 'true') return res.status(503).json({ error: 'Reserve with Google is not connected yet. Configure it in Settings once Google partner credentials are issued.' });

    const { google_booking_id, customer_name, customer_phone, customer_email, service_name, start_time, end_time } = req.body;
    if (!google_booking_id) return res.status(400).json({ error: 'google_booking_id required (idempotency key)' });

    // Idempotent — Google may retry this call, so re-sending the same booking ID
    // should not create duplicates.
    const { data: existing } = await supabase.from('google_bookings').select('*').eq('google_booking_id', google_booking_id).single();
    if (existing) return res.json(existing);

    const { data, error } = await supabase.from('google_bookings').insert({
      google_booking_id, customer_name, customer_phone, customer_email, service_name,
      start_time, end_time, status: 'pending', raw_payload: req.body
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await createNotification('new_booking', 'New Google Reserve Appointment', `${customer_name || 'Customer'} — ${service_name || 'Service'}`);
    res.json(data);
  } catch(e) {
    console.error('Google Reserve booking webhook error:', e.message);
    res.status(500).json({ error: 'Internal error processing booking' });
  }
});

app.get('/api/google-reserve/bookings', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('google_bookings').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/google-reserve/bookings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Converts a received Google booking into a real CRM job — same pattern as the
// old manual booking-confirm flow, just sourced from Google instead.
app.put('/api/google-reserve/bookings/:id/confirm', authMiddleware, async (req, res) => {
  try {
  const { tech_id, tech_name } = req.body;
    const { data: booking } = await supabase.from('google_bookings').select('*').eq('id', req.params.id).single();
    if (!booking) return res.status(404).json({ error: 'Booking not found' });

    let customer = await supabase.from('customers').select('*').eq('phone', booking.customer_phone).single();
    let customerRow = customer.data;
    if (!customerRow && booking.customer_phone) {
      const created = await supabase.from('customers').insert({ name: booking.customer_name, phone: booking.customer_phone, email: booking.customer_email }).select().single();
      customerRow = created.data;
    }
    const count = await supabase.from('jobs').select('id', { count: 'exact' });
    const num = String((count.count || 0) + 1).padStart(3, '0');
    const jobId = `JOB-${num}`;
    await supabase.from('jobs').insert({
      id: jobId, title: booking.service_name || 'Reserve with Google Appointment', customer_id: customerRow?.id,
      customer_name: booking.customer_name, phone: booking.customer_phone, tech_id: tech_id || null, tech_name: tech_name || null,
      status: tech_id ? 'assigned' : 'new', priority: 'med', job_date: todayInBusinessTz(), scheduled_date: booking.start_time,
      source: 'Reserve with Google'
    });
    await supabase.from('google_bookings').update({ status: 'confirmed', job_id: jobId }).eq('id', req.params.id);
    runEventWorkflows('new_booking', { id: jobId, customer_name: booking.customer_name, job_type: booking.service_name }).catch(() => {});
    res.json({ success: true, job_id: jobId });
  } catch(e) {
    console.error('/api/google-reserve/bookings/:id/confirm error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/google-reserve/bookings/:id/cancel', authMiddleware, async (req, res) => {
  try {
  await supabase.from('google_bookings').update({ status: 'cancelled' }).eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/google-reserve/bookings/:id/cancel error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/receipt/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'receipt.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

// Public — no auth. Token is unguessable (random), this is the only key protecting it.
app.get('/api/receipt/:token', async (req, res) => {
  try {
  const { data: inv } = await supabase.from('invoices').select('*').eq('receipt_token', req.params.token).single();
    if (!inv) return res.status(404).json({ error: 'Receipt not found' });
    const { data: s } = await supabase.from('settings').select('key,value');
    const settings = {}; s?.forEach(x => settings[x.key] = x.value);
    // Never expose internal cost breakdown — only total + optional manual breakdown the admin chose to show.
    res.json({
      invoice_id: inv.id,
      customer_name: inv.customer_name,
      total: inv.total,
      invoice_date: inv.invoice_date,
      status: inv.status,
      breakdown: inv.receipt_breakdown || null, // [{label, amount}] manually set by admin, or null = total only
      business_name: settings.business_name || 'Express Lock&Key',
      business_phone: settings.business_phone || '',
      business_email: settings.business_email || '',
      review_link: settings.review_link || ''
    });
  } catch(e) {
    console.error('/api/receipt/:token error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── EXPRESS ERROR HANDLER ──────────────────────────────────────────────────────
// Catches errors thrown synchronously inside route handlers (Express doesn't
// auto-catch these the way it catches rejected promises in newer versions) and
// returns a clean JSON error instead of letting it bubble up and potentially
// crash the process. This must be registered after all other app.use()/app.get()
// calls — Express only treats a 4-argument function as an error handler.
app.use((err, req, res, next) => {
  console.error('Express error handler caught:', err?.message, err?.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FieldPro CRM running on port ${PORT}`);
  startAlertEngine().catch(e => console.error('Alert engine failed to start:', e.message));
});

// ─── BOOKINGS ─────────────────────────────────────────────────────────────────

// ─── LIVE EVENT-TRIGGERED WORKFLOWS ─────────────────────────────────────────────
// Runs whenever a real event happens (new_job, job_assigned, status_change),
// checking each active workflow's trigger_condition against the job. Conditions
// support tags and status, not just arbitrary fields, since those are the two
// most useful checks dispatchers actually use day to day.
async function runEventWorkflows(triggerEvent, jobData) {
  try {
    const { data: workflows } = await supabase.from('workflows').select('*').eq('trigger_type', 'event').eq('trigger_event', triggerEvent).eq('active', true);
    for (const wf of (workflows || [])) {
      if (!workflowConditionMatches(wf.trigger_condition, jobData)) continue;
      const { data: tech } = jobData.tech_id ? await supabase.from('users').select('phone').eq('id', jobData.tech_id).single() : { data: null };
      const actionData = { ...jobData, tech_phone: tech?.phone || null };
      await executeWorkflowActions(wf.actions, actionData);
      await supabase.from('workflows').update({ run_count: (wf.run_count || 0) + 1, last_run: new Date().toISOString() }).eq('id', wf.id);
    }
  } catch(e) { console.log('Event workflow error:', e.message); }
}

// Evaluates a workflow's trigger_condition against a job. Supports:
//   { field: 'tags', operator: 'contains', value: 'VIP' }       — tag-based
//   { field: 'status', operator: 'equals', value: 'in-progress' } — status-based
//   { field: <any job column>, operator: 'equals'|'contains', value: ... } — generic
// No condition set (empty {}) always matches.
function workflowConditionMatches(condition, jobData) {
  if (!condition || !condition.field || condition.value === undefined || condition.value === '') return true;
  const fieldVal = jobData[condition.field];
  if (condition.field === 'tags') {
    const tags = jobData.tags || [];
    return tags.includes(condition.value);
  }
  if (condition.operator === 'equals') return fieldVal === condition.value;
  if (condition.operator === 'contains') return String(fieldVal || '').toLowerCase().includes(String(condition.value).toLowerCase());
  return true;
}


// ─── WORKFLOWS (Zapier-style) ─────────────────────────────────────────────────

app.get('/api/workflows', authMiddleware, requirePerm('perm_view_workflows'), async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').select('*').order('created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/workflows', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').insert(req.body).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('workflows').update(req.body).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/workflows/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.delete('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
  await supabase.from('workflows').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/workflows/:id error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/workflows/:id/test', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data: wf } = await supabase.from('workflows').select('*').eq('id', req.params.id).single();
    if (!wf) return res.status(404).json({ error: 'Not found' });
    const testData = { customer_name: 'Test Customer', job_id: 'JOB-001', job_type: 'Car Lockout', address: '123 Test St', tech_name: 'Test Tech', phone: req.body.test_phone || '', revenue: '0', total_jobs: '1', pending: '0' };
    const result = await executeWorkflowActions(wf.actions, testData);
    await supabase.from('workflows').update({ run_count: (wf.run_count||0)+1, last_run: new Date().toISOString() }).eq('id', req.params.id);
    res.json({ success: true, result });
  } catch(e) {
    console.error('/api/workflows/:id/test error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

async function executeWorkflowActions(actions, data) {
  const results = [];
  const { data: s } = await supabase.from('settings').select('key,value');
  const settings = {}; s?.forEach(x => settings[x.key] = x.value);
  for (const action of (actions || [])) {
    try {
      const msg = (action.message || '').replace(/{(\w+)}/g, (_, k) => data[k] || '');
      const toPhone = action.to === 'customer' ? data.phone : action.to === 'tech' ? data.tech_phone : action.phone;
      if (action.type === 'send_sms' && toPhone) {
        await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: toPhone });
        results.push({ action: 'send_sms', to: toPhone, status: 'sent' });
      } else if (action.type === 'send_whatsapp' && toPhone) {
        const waFrom = settings.whatsapp_from || 'whatsapp:+14155238886';
        const waTo = toPhone.startsWith('whatsapp:') ? toPhone : `whatsapp:${toPhone}`;
        await twilioClient.messages.create({ body: msg, from: waFrom, to: waTo });
        results.push({ action: 'send_whatsapp', to: toPhone, status: 'sent' });
      } else if (action.type === 'create_notification') {
        await createNotification('workflow', action.title || 'Workflow', msg);
        results.push({ action: 'notification', status: 'created' });
      } else if (action.type === 'update_status' && data.id) {
        await supabase.from('jobs').update({ status: action.status }).eq('id', data.id);
        results.push({ action: 'update_status', status: action.status });
      } else if (action.type === 'assign_tag' && data.id) {
        const { data: j } = await supabase.from('jobs').select('tags').eq('id', data.id).single();
        const tags = [...(j?.tags || [])]; if (!tags.includes(action.tag)) tags.push(action.tag);
        await supabase.from('jobs').update({ tags }).eq('id', data.id);
        results.push({ action: 'assign_tag', tag: action.tag });
      } else if (action.type === 'webhook_post' && action.url) {
        const r = await fetch(action.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, message: msg }) });
        results.push({ action: 'webhook', url: action.url, status: r.status });
      } else if (action.type === 'send_report') {
        const report = await generateDailyReport();
        const reportMsg = msg.replace('{total_jobs}', report.total).replace('{pending}', report.pending).replace('{revenue}', report.revenue);
        if (settings.admin_phone) {
          await twilioClient.messages.create({ body: reportMsg, from: process.env.TWILIO_PHONE_NUMBER, to: settings.admin_phone });
        }
        results.push({ action: 'send_report', status: 'sent' });
      }
    } catch(e) { results.push({ action: action.type, status: 'error', error: e.message }); }
  }
  return results;
}

async function generateDailyReport() {
  const today = todayInBusinessTz();
  const { data: jobs } = await supabase.from('jobs').select('*').eq('job_date', today);
  const { data: invoices } = await supabase.from('invoices').select('*').eq('invoice_date', today).eq('status', 'paid');
  const revenue = invoices?.reduce((a, i) => a + (i.total || 0), 0) || 0;
  return { total: jobs?.length || 0, pending: jobs?.filter(j => j.status === 'new').length || 0, revenue: revenue.toFixed(2) };
}

// Scheduled workflow runner (call this endpoint via cron or external scheduler)
app.post('/api/admin-report/test', authMiddleware, adminOnly, async (req, res) => {
  try {
  await sendAdminReport('manual', '✅ FieldPro test message — if you see this, your admin reporting channel is working.');
    const { data: log } = await supabase.from('admin_report_log').select('*').order('created_at', { ascending: false }).limit(3);
    res.json({ success: true, attempts: log || [] });
  } catch(e) {
    console.error('/api/admin-report/test error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin-report/log', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { data, error } = await supabase.from('admin_report_log').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/admin-report/log error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/workflows/run-scheduled', async (req, res) => {
  try {
  const secret = req.headers['x-cron-secret'];
    if (secret !== process.env.JWT_SECRET) return res.status(401).json({ error: 'Unauthorized' });
    const now = new Date();
    const { data: workflows } = await supabase.from('workflows').select('*').eq('trigger_type', 'schedule').eq('active', true);
    let ran = 0;
    for (const wf of (workflows || [])) {
      const shouldRun = checkSchedule(wf.trigger_schedule, now, wf.last_run);
      if (shouldRun) {
        const report = await generateDailyReport();
        await executeWorkflowActions(wf.actions, { ...report, phone: '' });
        await supabase.from('workflows').update({ run_count: (wf.run_count||0)+1, last_run: now.toISOString() }).eq('id', wf.id);
        ran++;
      }
    }
    res.json({ success: true, workflows_ran: ran });
  } catch(e) {
    console.error('/api/workflows/run-scheduled error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

function checkSchedule(schedule, now, lastRun) {
  if (!schedule) return false;
  const last = lastRun ? new Date(lastRun) : new Date(0);
  const hoursSinceLast = (now - last) / (1000 * 60 * 60);
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: BUSINESS_TZ, weekday: 'short', hour: 'numeric', hour12: false }).formatToParts(now);
  const map = {}; parts.forEach(p => map[p.type] = p.value);
  const hourEastern = parseInt(map.hour) % 24;
  const dayEastern = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(map.weekday);
  if (schedule === 'hourly') return hoursSinceLast >= 1;
  if (schedule === 'daily_8am') return hourEastern === 8 && hoursSinceLast >= 23;
  if (schedule === 'daily_6pm') return hourEastern === 18 && hoursSinceLast >= 23;
  if (schedule === 'weekly_monday') return dayEastern === 1 && hoursSinceLast >= 167;
  return false;
}

// ─── AI ASSISTANT ─────────────────────────────────────────────────────────────

app.get('/api/ai-chat', authMiddleware, async (req, res) => {
  try {
  const { data, error } = await supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(50);
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/ai-chat error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/ai-chat/clear', authMiddleware, async (req, res) => {
  try {
  await supabase.from('ai_chat').delete().eq('user_id', req.user.id);
    res.json({ success: true });
  } catch(e) {
    console.error('/api/ai-chat/clear error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.post('/api/ai-assistant', authMiddleware, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  try {
    // Gather CRM context
    const [{ data: jobs }, { data: customers }, { data: techs }, { data: invoices }, { data: history }] = await Promise.all([
      supabase.from('jobs').select('*').order('created_at', { ascending: false }).limit(50),
      supabase.from('customers').select('*').limit(30),
      supabase.from('users').select('id,name,role,status,color,initials').eq('role', 'tech'),
      supabase.from('invoices').select('*').order('created_at', { ascending: false }).limit(30),
      supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(10)
    ]);

    const today = todayInBusinessTz();
    const revenue = invoices?.filter(i => i.status === 'paid').reduce((a, i) => a + (i.total || 0), 0) || 0;
    const outstanding = invoices?.filter(i => i.status === 'unpaid').reduce((a, i) => a + (i.total || 0), 0) || 0;

    const systemPrompt = `You are the AI assistant for Express Lock&Key CRM. You have full access to the business data and can execute tasks directly.

CURRENT CRM DATA:
- Total Jobs: ${jobs?.length || 0}
- New/Pending: ${jobs?.filter(j => j.status === 'new').length || 0}
- In Progress: ${jobs?.filter(j => j.status === 'in-progress').length || 0}
- Done Today: ${jobs?.filter(j => j.job_date === today && j.status === 'done').length || 0}
- Technicians: ${techs?.map(t => t.name + ' (' + t.status + ')').join(', ')}
- Revenue Collected: $${revenue.toFixed(2)}
- Outstanding: $${outstanding.toFixed(2)}
- Recent Jobs: ${jobs?.slice(0, 10).map(j => j.id + ' ' + j.title + ' ' + j.customer_name + ' [' + j.status + ']').join('; ')}

WHAT YOU CAN DO:
1. Answer questions about jobs, revenue, techs, customers
2. Give instructions for actions prefixed with [ACTION]:
   - [ACTION:assign_tech] job_id=JOB-001 tech_name=Marcus R.
   - [ACTION:update_status] job_id=JOB-001 status=done
   - [ACTION:send_sms] phone=+13055550101 message=Your text here
   - [ACTION:create_job] title=Car Lockout customer=John phone=+1305... address=123 Main St
   - [ACTION:send_report] type=daily
   - [ACTION:add_tag] job_id=JOB-001 tag=VIP

Be concise, direct, and professional. When executing actions, confirm what you did. If asked to do multiple things, list each action clearly.`;

    const messages = [
      ...(history || []).map(h => ({ role: h.role, content: h.content })),
      { role: 'user', content: message }
    ];

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, system: systemPrompt, messages })
    });
    const aiData = await aiRes.json();
    const reply = aiData.content?.[0]?.text || 'Sorry, I could not process that.';

    // Parse and execute any actions in the reply
    const actionsTaken = [];
    const actionRegex = /\[ACTION:(\w+)\]\s*([^\n]*)/g;
    let match;
    while ((match = actionRegex.exec(reply)) !== null) {
      const actionType = match[1];
      const params = {};
      // Params are space-separated key=value pairs, but values themselves (addresses,
      // SMS text, names) can contain spaces — so split only on spaces that precede
      // the next "word=" pattern, not every space in the line.
      const paramStr = match[2];
      const paramRegex = /(\w+)=((?:(?!\s+\w+=).)*)/g;
      let pMatch;
      while ((pMatch = paramRegex.exec(paramStr)) !== null) {
        params[pMatch[1]] = pMatch[2].trim();
      }
      try {
        if (actionType === 'assign_tech' && params.job_id && params.tech_name) {
          const tech = techs?.find(t => t.name.toLowerCase().includes(params.tech_name.toLowerCase()));
          if (tech) { await supabase.from('jobs').update({ tech_id: tech.id, tech_name: tech.name, status: 'assigned' }).eq('id', params.job_id); actionsTaken.push('Assigned ' + tech.name + ' to ' + params.job_id); }
        } else if (actionType === 'update_status' && params.job_id) {
          await supabase.from('jobs').update({ status: params.status }).eq('id', params.job_id); actionsTaken.push('Updated ' + params.job_id + ' to ' + params.status);
        } else if (actionType === 'send_sms' && params.phone) {
          await twilioClient.messages.create({ body: params.message || '', from: process.env.TWILIO_PHONE_NUMBER, to: params.phone }); actionsTaken.push('SMS sent to ' + params.phone);
        } else if (actionType === 'add_tag' && params.job_id) {
          const { data: j } = await supabase.from('jobs').select('tags').eq('id', params.job_id).single();
          const tags = [...(j?.tags || [])]; if (!tags.includes(params.tag)) tags.push(params.tag);
          await supabase.from('jobs').update({ tags }).eq('id', params.job_id); actionsTaken.push('Added tag ' + params.tag + ' to ' + params.job_id);
        } else if (actionType === 'send_report') {
          const report = await generateDailyReport(); actionsTaken.push('Report generated: ' + JSON.stringify(report));
        } else if (actionType === 'create_job' && params.title && params.customer && params.phone) {
          let customer = await supabase.from('customers').select('*').eq('phone', params.phone).single();
          let customerRow = customer.data;
          if (!customerRow) {
            const created = await supabase.from('customers').insert({ name: params.customer, phone: params.phone, address: params.address || null }).select().single();
            customerRow = created.data;
          }
          const count = await supabase.from('jobs').select('id', { count: 'exact' });
          const num = String((count.count || 0) + 1).padStart(3, '0');
          const newJobId = `JOB-${num}`;
          await supabase.from('jobs').insert({
            id: newJobId, title: params.title, customer_id: customerRow?.id, customer_name: params.customer,
            phone: params.phone, address: params.address || null, status: 'new', priority: 'med', job_date: todayInBusinessTz()
          });
          actionsTaken.push('Created job ' + newJobId + ' for ' + params.customer);
        }
      } catch(e) { actionsTaken.push('Action failed: ' + e.message); }
    }

    // Save to chat history
    await supabase.from('ai_chat').insert([
      { user_id: req.user.id, role: 'user', content: message },
      { user_id: req.user.id, role: 'assistant', content: reply, actions_taken: actionsTaken }
    ]);

    res.json({ reply, actions_taken: actionsTaken });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── EDITABLE INVOICES ────────────────────────────────────────────────────────

app.put('/api/invoices/:id/edit', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { line_items, parts_items, tax_rate, tech_commission_type, tech_commission_value, notes } = req.body;
    const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    // Save edit history
    const editHistory = [...(inv.edit_history || []), { edited_by: req.user.name, edited_at: new Date().toISOString(), previous: { line_items: inv.line_items, subtotal: inv.subtotal, total: inv.total } }];
    const all_items = [...(line_items || []), ...(parts_items || [])];
    const labor_cost = (line_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const parts_cost = (parts_items || []).reduce((a, i) => a + (i.qty * i.rate), 0);
    const subtotal = labor_cost + parts_cost;
    const tr = parseFloat(tax_rate) || inv.tax_rate || 8.5;
    const tax_amount = subtotal * (tr / 100);
    const total = subtotal + tax_amount;
    let tech_commission_amount = 0;
    const commType = tech_commission_type || inv.tech_commission_type || 'percentage';
    const commVal = parseFloat(tech_commission_value) || inv.tech_commission_value || 0;
    if (commType === 'percentage') tech_commission_amount = subtotal * (commVal / 100);
    else tech_commission_amount = commVal;
    const { data, error } = await supabase.from('invoices').update({
      line_items: all_items, labor_cost, parts_cost, subtotal, tax_rate: tr, tax_amount, total,
      tech_commission_type: commType, tech_commission_value: commVal, tech_commission_amount, notes,
      edit_history: editHistory, last_edited_by_user_id: req.user.id, last_edited_by_name: req.user.name, last_edited_at: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logAudit('invoice', req.params.id, req.user.id, req.user.name, 'edited', `Edited invoice — new total $${total.toFixed(2)}`);
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/edit error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Manual receipt breakdown — only affects what the customer sees on the public receipt page.
// Internal invoice (commission, real costs) stays untouched. Pass breakdown: null to clear it
// and just show the total again.
app.put('/api/invoices/:id/receipt-breakdown', authMiddleware, async (req, res) => {
  try {
  const { breakdown } = req.body; // [{label, amount}] or null
    const { data, error } = await supabase.from('invoices').update({ receipt_breakdown: breakdown }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/invoices/:id/receipt-breakdown error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Reopen a closed job
app.put('/api/jobs/:id/reopen', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { reason } = req.body;
    const { data, error } = await supabase.from('jobs').update({ status: 'in-progress', reopened_at: new Date().toISOString(), reopen_reason: reason || 'Reopened by admin', close_date: null }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    await logHistory(req.params.id, req.user.id, req.user.name, 'Job reopened', 'status', 'done', 'in-progress');
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/:id/reopen error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});


// ─── CUSTOM STATUS LABELS ─────────────────────────────────────────────────────
app.get('/api/status-labels', authMiddleware, async (req, res) => {
  try {
  const { data } = await supabase.from('settings').select('value').eq('key', 'custom_status_labels').single();
    const labels = data?.value ? JSON.parse(data.value) : ['new','assigned','in-progress','done','cancelled'];
    res.json(labels);
  } catch(e) {
    console.error('/api/status-labels error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

app.put('/api/status-labels', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { labels } = req.body;
    await supabase.from('settings').upsert({ key: 'custom_status_labels', value: JSON.stringify(labels) });
    res.json({ success: true, labels });
  } catch(e) {
    console.error('/api/status-labels error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── DASHBOARD ANALYTICS ──────────────────────────────────────────────────────
app.get('/api/analytics/dashboard', authMiddleware, adminOnly, async (req, res) => {
  try {
  const now = new Date();
    const today = todayInBusinessTz();
    const nowEastern = nowInBusinessTz();
    const weekStart = new Date(nowEastern); weekStart.setDate(nowEastern.getDate() - nowEastern.getDay());
    const monthStart = new Date(nowEastern.getFullYear(), nowEastern.getMonth(), 1);
    const isAdmin = req.user.role === 'admin';
    let canSeeRevenue = isAdmin;
    if (!isAdmin) {
      const { data: u } = await supabase.from('users').select('perm_view_total_revenue').eq('id', req.user.id).single();
      canSeeRevenue = u?.perm_view_total_revenue === true;
    }

    const [{ data: jobs }, { data: invoices }, { data: techs }] = await Promise.all([
      supabase.from('jobs').select('*').order('created_at', { ascending: false }),
      supabase.from('invoices').select('*'), // per-job invoice data is fine for dispatchers — they handle individual job finance
      supabase.from('users').select('id,name,color,initials,role').eq('role', 'tech')
    ]);

    const todayJobs = jobs?.filter(j => j.job_date === today) || [];
    const weekJobs = jobs?.filter(j => new Date(j.job_date) >= weekStart) || [];
    const monthJobs = jobs?.filter(j => new Date(j.job_date) >= monthStart) || [];

    // Jobs by status
    const statusCounts = {};
    (jobs || []).forEach(j => { statusCounts[j.status] = (statusCounts[j.status] || 0) + 1; });

    // Jobs by type
    const typeCounts = {};
    (jobs || []).forEach(j => { if(j.job_type) typeCounts[j.job_type] = (typeCounts[j.job_type] || 0) + 1; });

    // Tech performance — per-tech revenue is visible to dispatchers (it's per-job, not company total),
    // only the aggregate company-wide revenue object below is gated by canSeeRevenue.
    const techPerf = (techs || []).map(t => {
      const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
      const tInvoices = invoices?.filter(i => i.tech_id === t.id && i.status === 'paid') || [];
      return {
        tech: t,
        total: tJobs.length,
        done: tJobs.filter(j => j.status === 'done').length,
        cancelled: tJobs.filter(j => j.status === 'cancelled').length,
        inProgress: tJobs.filter(j => j.status === 'in-progress').length,
        revenue: tInvoices.reduce((a, i) => a + (i.total || 0), 0),
        completionRate: tJobs.length ? Math.round(tJobs.filter(j => j.status === 'done').length / tJobs.length * 100) : 0
      };
    });

    // Last 7 days job trend
    const last7 = [];
    for(let i=6; i>=0; i--) {
      const d = new Date(nowEastern); d.setDate(nowEastern.getDate() - i);
      const ds = dateInBusinessTz(d);
      const dayJobs = jobs?.filter(j => j.job_date === ds) || [];
      last7.push({ date: ds, label: d.toLocaleDateString('en-US',{weekday:'short'}), total: dayJobs.length, done: dayJobs.filter(j=>j.status==='done').length, cancelled: dayJobs.filter(j=>j.status==='cancelled').length });
    }

    // Company-wide revenue totals — confidential, gated by canSeeRevenue
    const revenueData = canSeeRevenue ? {
      today: invoices?.filter(i=>i.invoice_date===today&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
      week: invoices?.filter(i=>new Date(i.invoice_date)>=weekStart&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
      month: invoices?.filter(i=>new Date(i.invoice_date)>=monthStart&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
      outstanding: invoices?.filter(i=>i.status==='unpaid').reduce((a,i)=>a+(i.total||0),0) || 0
    } : null;

    // ── EXPANDED ANALYTICS ──────────────────────────────────────────────────────
    const lastWeekStart = new Date(weekStart); lastWeekStart.setDate(lastWeekStart.getDate() - 7);
    const lastWeekEnd = new Date(weekStart); lastWeekEnd.setMilliseconds(-1);
    const lastWeekJobs = jobs?.filter(j => new Date(j.job_date) >= lastWeekStart && new Date(j.job_date) <= lastWeekEnd) || [];
    const lastMonthStart = new Date(nowEastern.getFullYear(), nowEastern.getMonth() - 1, 1);
    const lastMonthEnd = new Date(monthStart); lastMonthEnd.setMilliseconds(-1);
    const lastMonthJobs = jobs?.filter(j => new Date(j.job_date) >= lastMonthStart && new Date(j.job_date) <= lastMonthEnd) || [];

    // Week-over-week / month-over-month growth — jobs count and revenue, with % change.
    // null revenue values mean "hidden, not zero" so the frontend doesn't show a misleading 0%.
    function pctChange(curr, prev) { if (!prev) return curr > 0 ? 100 : 0; return Math.round(((curr - prev) / prev) * 100); }
    const weekRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= weekStart && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const lastWeekRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= lastWeekStart && new Date(i.invoice_date) <= lastWeekEnd && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const monthRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= monthStart && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const lastMonthRevenue = canSeeRevenue ? (invoices?.filter(i => new Date(i.invoice_date) >= lastMonthStart && new Date(i.invoice_date) <= lastMonthEnd && i.status === 'paid').reduce((a,i) => a+(i.total||0), 0) || 0) : null;
    const growth = {
      jobs_wow: pctChange(weekJobs.length, lastWeekJobs.length),
      jobs_mom: pctChange(monthJobs.length, lastMonthJobs.length),
      revenue_wow: canSeeRevenue ? pctChange(weekRevenue, lastWeekRevenue) : null,
      revenue_mom: canSeeRevenue ? pctChange(monthRevenue, lastMonthRevenue) : null
    };

    // Average job value trend over the last 8 weeks — shows whether typical job size is rising or falling.
    const avgJobValueTrend = [];
    if (canSeeRevenue) {
      for (let w = 7; w >= 0; w--) {
        const wStart = new Date(weekStart); wStart.setDate(wStart.getDate() - w * 7);
        const wEnd = new Date(wStart); wEnd.setDate(wEnd.getDate() + 6);
        const wInvoices = invoices?.filter(i => new Date(i.invoice_date) >= wStart && new Date(i.invoice_date) <= wEnd && i.status === 'paid') || [];
        const avg = wInvoices.length ? wInvoices.reduce((a,i) => a+(i.total||0), 0) / wInvoices.length : 0;
        avgJobValueTrend.push({ label: wStart.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), avg: Math.round(avg * 100) / 100, count: wInvoices.length });
      }
    }

    // Average tech response time (assignment -> confirmation), in minutes, over confirmed jobs.
    const confirmedJobs = (jobs || []).filter(j => j.confirmed_by_tech && j.assigned_at && j.confirmed_at);
    const avgResponseMinutes = confirmedJobs.length
      ? Math.round(confirmedJobs.reduce((a, j) => a + (new Date(j.confirmed_at) - new Date(j.assigned_at)) / 60000, 0) / confirmedJobs.length)
      : null;

    // Repeat-customer rate — % of customers with more than one job, all time.
    const customerJobCounts = {};
    (jobs || []).forEach(j => { if (j.customer_id) customerJobCounts[j.customer_id] = (customerJobCounts[j.customer_id] || 0) + 1; });
    const totalCustomersWithJobs = Object.keys(customerJobCounts).length;
    const repeatCustomers = Object.values(customerJobCounts).filter(c => c > 1).length;
    const repeatCustomerRate = totalCustomersWithJobs ? Math.round((repeatCustomers / totalCustomersWithJobs) * 100) : 0;

    // Busiest day-of-week and hour-of-day, all time — helps staffing decisions.
    const dayOfWeekCounts = [0,0,0,0,0,0,0]; // Sun-Sat
    const hourCounts = Array(24).fill(0);
    (jobs || []).forEach(j => {
      const d = new Date(j.created_at);
      const parts = new Intl.DateTimeFormat('en-US', { timeZone: BUSINESS_TZ, weekday: 'short', hour: 'numeric', hour12: false }).formatToParts(d);
      const map = {}; parts.forEach(p => map[p.type] = p.value);
      const dayIdx = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(map.weekday);
      const hour = parseInt(map.hour) % 24;
      if (dayIdx >= 0) dayOfWeekCounts[dayIdx]++;
      hourCounts[hour]++;
    });
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    const busiestDay = dayNames[dayOfWeekCounts.indexOf(Math.max(...dayOfWeekCounts))];
    const busiestHour = hourCounts.indexOf(Math.max(...hourCounts));

    // 30-day trend — same shape as last7 but extended, for a longer-range view.
    const last30 = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(nowEastern); d.setDate(nowEastern.getDate() - i);
      const ds = dateInBusinessTz(d);
      const dayJobs = jobs?.filter(j => j.job_date === ds) || [];
      last30.push({ date: ds, total: dayJobs.length, done: dayJobs.filter(j=>j.status==='done').length });
    }

    res.json({
      today: todayJobs, todayTotal: todayJobs.length, weekTotal: weekJobs.length, monthTotal: monthJobs.length,
      statusCounts, typeCounts, techPerf, last7, revenue: revenueData, totalJobs: jobs?.length || 0, cancelled: statusCounts['cancelled'] || 0,
      growth, avgJobValueTrend, avgResponseMinutes, repeatCustomerRate, busiestDay, busiestHour, last30
    });
  } catch(e) {
    console.error('/api/analytics/dashboard error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── 12-MONTH PERFORMANCE TREND ────────────────────────────────────────────────
// Month-by-month view of close rate, job volume, and revenue over the last year,
// with month-over-month % change on every metric. Optionally filtered to a single
// tech. This is the "how are we doing, are we growing" view — distinct from the
// day-to-day dashboard, built for understanding trajectory over real time.
app.get('/api/analytics/yearly-trend', authMiddleware, adminOnly, async (req, res) => {
  try {
  const techId = req.query.tech_id || null;
    // Comma-separated list of tech IDs to exclude from the "all techs" view — lets
    // Hassan untick specific techs to see growth trends without their numbers,
    // e.g. to check if overall growth is broad-based or driven by one person.
    const excludeTechIds = (req.query.exclude_tech_ids || '').split(',').map(s => s.trim()).filter(Boolean);
    const nowE = nowInBusinessTz();

    let jobsQuery = supabase.from('jobs').select('id,status,job_date,created_at,tech_id,tech_name,invoice_id');
    if (techId) jobsQuery = jobsQuery.eq('tech_id', techId);
    let { data: jobs } = await jobsQuery;
    if (!techId && excludeTechIds.length) jobs = (jobs || []).filter(j => !excludeTechIds.includes(j.tech_id));

    let { data: invoices } = await supabase.from('invoices').select('id,total,status,invoice_date,tech_id,job_id');
    if (!techId && excludeTechIds.length) invoices = (invoices || []).filter(i => !excludeTechIds.includes(i.tech_id));

    const months = [];
    for (let i = 11; i >= 0; i--) {
      const m = new Date(nowE.getFullYear(), nowE.getMonth() - i, 1);
      const monthStart = new Date(m.getFullYear(), m.getMonth(), 1);
      const monthEnd = new Date(m.getFullYear(), m.getMonth() + 1, 0, 23, 59, 59);

      const monthJobsList = (jobs || []).filter(j => {
        const jd = new Date(j.job_date || j.created_at);
        return jd >= monthStart && jd <= monthEnd;
      });
      const closed = monthJobsList.filter(j => j.status === 'done').length;
      const total = monthJobsList.length;
      const closeRate = total ? Math.round((closed / total) * 100) : 0;

      const jobIdsThisMonth = new Set(monthJobsList.map(j => j.id));
      const monthInvoices = (invoices || []).filter(inv => {
        if (techId && inv.tech_id !== techId) return false;
        if (inv.status !== 'paid') return false;
        const id = new Date(inv.invoice_date);
        return id >= monthStart && id <= monthEnd;
      });
      const revenue = monthInvoices.reduce((a, inv) => a + (inv.total || 0), 0);

      months.push({
        label: m.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
        year: m.getFullYear(), month: m.getMonth(),
        total_jobs: total, closed_jobs: closed, close_rate: closeRate, revenue: Math.round(revenue * 100) / 100
      });
    }

    // Month-over-month % change on every metric, vs the previous month in the series
    function pct(curr, prev) { if (!prev) return curr > 0 ? 100 : 0; return Math.round(((curr - prev) / prev) * 100); }
    const trend = months.map((m, i) => {
      const prev = months[i - 1];
      return {
        ...m,
        jobs_change_pct: prev ? pct(m.total_jobs, prev.total_jobs) : null,
        close_rate_change_pct: prev ? pct(m.close_rate, prev.close_rate) : null,
        revenue_change_pct: prev ? pct(m.revenue, prev.revenue) : null
      };
    });

    // Year-over-year summary: this year's total so far vs the same months last year,
    // so Hassan can see broader trajectory, not just month-to-month noise.
    const thisYearTotal = trend.reduce((a, m) => a + m.total_jobs, 0);
    const thisYearRevenue = trend.reduce((a, m) => a + m.revenue, 0);
    const avgCloseRate = trend.length ? Math.round(trend.reduce((a, m) => a + m.close_rate, 0) / trend.length) : 0;

    res.json({ trend, summary: { total_jobs_12mo: thisYearTotal, total_revenue_12mo: Math.round(thisYearRevenue * 100) / 100, avg_close_rate_12mo: avgCloseRate } });
  } catch(e) {
    console.error('/api/analytics/yearly-trend error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── DAILY JOB BOARD ──────────────────────────────────────────────────────────
app.get('/api/jobs/daily-board', authMiddleware, async (req, res) => {
  try {
  const date = req.query.date || todayInBusinessTz();
    let query = supabase.from('jobs').select('*').eq('job_date', date).order('created_at');
    if (req.user.role !== 'admin') query = query.eq('tech_id', req.user.id);
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/jobs/daily-board error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// ─── CALL MASKING — INBOUND ROUTING ──────────────────────────────────────────
// When customer calls back the masked number, route to the tech
app.post('/api/webhooks/voice', async (req, res) => {
  const { From, To, CallSid } = req.body;
  res.set('Content-Type', 'text/xml');
  try {
    // Known customer calling back — route straight to whichever tech is currently
    // assigned on their active job, no menu needed. This takes priority over the
    // extension menu since a returning customer shouldn't have to dial anything.
    const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
    if (customer) {
      const { data: job } = await supabase.from('jobs').select('tech_id,tech_name').eq('customer_name', customer.name).in('status',['assigned','in-progress']).order('created_at',{ascending:false}).limit(1).single();
      if (job?.tech_id) {
        const { data: t } = await supabase.from('users').select('phone,name').eq('id', job.tech_id).single();
        if (t?.phone) {
          await createNotification('inbound_call', `Inbound call from ${customer.name}`, `Customer calling back — routing to ${t.name}`);
          return res.send(`<Response><Say>Please hold while we connect you.</Say><Dial record="true" recordingStatusCallback="/api/webhooks/recording"><Number>${t.phone}</Number></Dial></Response>`);
        }
      }
    }

    // Anyone else (techs on any phone, dispatch, etc.) gets the extension menu —
    // no caller-identity check, since whoever has a valid 3-digit code for an
    // active job should be able to use it.
    res.send(`<Response><Gather numDigits="3" timeout="8" action="/api/webhooks/voice/extension" method="POST"><Say>Welcome to Field Pro. Please enter the 3 digit extension for your job, followed by the pound key.</Say></Gather><Say>No input received. Goodbye.</Say></Response>`);
    // Log call (after response — fine, doesn't delay the caller)
    await supabase.from('call_recordings').insert({ tech_name: 'Inbound', customer_name: customer?.name || From, call_sid: CallSid, direction: 'inbound' }).catch(()=>{});
  } catch(e) {
    console.error('Voice webhook error:', e.message);
    if (!res.headersSent) res.send('<Response><Say>We are experiencing technical difficulties. Please try again shortly.</Say></Response>');
  }
});

// Tech entered a 3-digit extension on the IVR menu. Looks up the job, validates
// the extension hasn't expired, and connects the call to the customer's real
// number — which is never spoken or exposed to the tech, only dialed by Twilio.
app.post('/api/webhooks/voice/extension', async (req, res) => {
  const { From, Digits, CallSid } = req.body;
  res.set('Content-Type', 'text/xml');
  try {
    const ext = (Digits || '').replace('#', '').padStart(3, '0').slice(-3);

    const { data: job } = await supabase.from('jobs').select('*').eq('call_extension', ext).eq('extension_active', true).single();

    if (!job) {
      await supabase.from('extension_call_log').insert({ extension: ext, caller_number: From, outcome: 'invalid' }).catch(() => {});
      return res.send(`<Response><Say>That extension is not valid or has expired. Please contact dispatch. Goodbye.</Say></Response>`);
    }

    const customerPhone = job.phone;
    if (!customerPhone) {
      await supabase.from('extension_call_log').insert({ extension: ext, job_id: job.id, caller_number: From, outcome: 'no_customer_phone' }).catch(() => {});
      return res.send(`<Response><Say>No customer phone number is on file for this job. Please contact dispatch. Goodbye.</Say></Response>`);
    }

    await supabase.from('jobs').update({ extension_last_used_at: new Date().toISOString() }).eq('id', job.id);
    await supabase.from('extension_call_log').insert({ extension: ext, job_id: job.id, caller_number: From, outcome: 'connected' }).catch(() => {});
    await supabase.from('call_recordings').insert({ tech_name: job.tech_name || 'Tech', customer_name: job.customer_name, call_sid: CallSid, direction: 'outbound' }).catch(() => {});

    res.send(`<Response><Say>Connecting you now.</Say><Dial record="true" recordingStatusCallback="/api/webhooks/recording" callerId="${process.env.TWILIO_PHONE_NUMBER}"><Number>${customerPhone}</Number></Dial></Response>`);
  } catch(e) {
    console.error('Extension webhook error:', e.message);
    if (!res.headersSent) res.send('<Response><Say>We are experiencing technical difficulties. Please contact dispatch. Goodbye.</Say></Response>');
  }
});

// ─── AI CALL SUMMARY ──────────────────────────────────────────────────────────
// Requests a real transcription from Twilio for this recording (if not already
// requested), or generates a genuine AI summary from the actual transcript text
// once it's ready. Requires a Twilio Transcription Configuration to be set up
// once in the Twilio Console — see deploy notes. Until that's configured, this
// returns a clear "not configured" message instead of fabricating a summary.
app.post('/api/recordings/:id/summarize', authMiddleware, async (req, res) => {
  try {
    const { data: rec } = await supabase.from('call_recordings').select('*').eq('id', req.params.id).single();
    if (!rec) return res.status(404).json({ error: 'Recording not found' });

    const { data: configSetting } = await supabase.from('settings').select('value').eq('key', 'twilio_transcription_config_sid').single();
    const configSid = configSetting?.value;
    if (!configSid) {
      return res.status(400).json({ error: 'Transcription is not set up yet. Go to Settings → Call Transcription to configure it.' });
    }

    // Already have a real transcript — summarize the actual words spoken.
    if (rec.transcript_status === 'completed' && rec.transcript_text) {
      const prompt = `Summarize this real phone call transcript for a locksmith business. Call was between ${rec.tech_name || 'a technician'} and ${rec.customer_name || 'a customer'}.\n\nTRANSCRIPT:\n${rec.transcript_text}\n\nProvide: 1) Brief overview of what was discussed, 2) Any commitments or follow-up actions mentioned, 3) Any flags (complaints, pricing disputes, scheduling issues). Keep it concise.`;
      const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
      });
      const aiData = await aiRes.json();
      const summary = aiData.content?.[0]?.text || 'Summary unavailable';
      await supabase.from('call_recordings').update({ call_summary: summary }).eq('id', req.params.id);
      return res.json({ summary, source: 'real_transcript' });
    }

    // Transcription already requested, still processing
    if (rec.transcript_status === 'pending') {
      return res.json({ summary: null, status: 'pending', message: 'Transcription is still processing — usually ready within a few minutes. Check back shortly.' });
    }

    // Not requested yet — submit it to Twilio now
    if (!rec.recording_sid) {
      return res.status(400).json({ error: 'No recording available for this call yet.' });
    }
    const resp = await fetch('https://intelligence.twilio.com/v3/Transcriptions', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ TranscriptionConfigurationSid: configSid, RecordingSid: rec.recording_sid })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.message || 'Twilio transcription request failed');
    await supabase.from('call_recordings').update({ transcription_sid: data.sid, transcript_status: 'pending' }).eq('id', req.params.id);
    res.json({ summary: null, status: 'pending', message: 'Transcription requested — check back in a few minutes.' });
  } catch(e) {
    console.error('/api/recordings/:id/summarize error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Twilio delivers the finished transcript here once processing completes.
app.post('/api/webhooks/transcription', async (req, res) => {
  try {
    const { transcription_sid, status, sentences } = req.body;
    const sid = req.body.TranscriptionSid || transcription_sid;
    const transcriptionStatus = req.body.Status || status;
    if (!sid) return res.status(400).send('Missing transcription SID');
    if (transcriptionStatus === 'completed') {
      // Sentence text arrives via webhook payload per Twilio's V3 API
      const text = (req.body.TranscriptText || (Array.isArray(sentences) ? sentences.map(s => s.transcript || s.text).join(' ') : '')) || '';
      await supabase.from('call_recordings').update({ transcript_text: text, transcript_status: 'completed' }).eq('transcription_sid', sid);
    } else if (transcriptionStatus === 'failed') {
      await supabase.from('call_recordings').update({ transcript_status: 'failed' }).eq('transcription_sid', sid);
    }
    res.sendStatus(200);
  } catch(e) {
    console.error('Transcription webhook error:', e.message);
    res.sendStatus(200); // acknowledge anyway so Twilio doesn't retry indefinitely
  }
});


// ─── WORKFLOWS TABLE MIGRATION ────────────────────────────────────────────────
// Fix existing automations table — workflows is the new table
// Both exist side by side


// ─── TECH CALL MASKING SETTINGS ───────────────────────────────────────────────

app.put('/api/users/:id/call-settings', authMiddleware, adminOnly, async (req, res) => {
  try {
  const { use_masking, direct_phone } = req.body;
    const { data, error } = await supabase.from('users')
      .update({ use_masking: use_masking !== undefined ? use_masking : true, direct_phone: direct_phone || null })
      .eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) {
    console.error('/api/users/:id/call-settings error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

// Updated masked call — respects per-tech masking setting

// ─── AUTO RECEIPT + REVIEW LINK ───────────────────────────────────────────────

app.post('/api/jobs/:id/auto-close-receipt', authMiddleware, async (req, res) => {
  try {
    const { data: job } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
    if (!job) return res.status(404).json({ error: 'Job not found' });
    const { data: inv } = await supabase.from('invoices').select('*').eq('job_id', req.params.id).single();
    const { data: customer } = await supabase.from('customers').select('*').eq('id', job.customer_id).single();
    const { data: s } = await supabase.from('settings').select('key,value');
    const settings = {}; s?.forEach(x => settings[x.key] = x.value);
    const reviewLink = settings.review_link || '';
    const bizName = settings.business_name || 'Express Lock&Key';
    if (!customer?.phone) return res.json({ success: false, reason: 'No customer phone' });
    let msg = `Hi ${job.customer_name || customer.name}! Your job with ${bizName} is complete.`;
    if (inv) {
      const token = await ensureReceiptToken(inv.id);
      const link = `${req.protocol}://${req.get('host')}/receipt/${token}`;
      msg += ` Here's your receipt: ${link}`;
    }
    msg += ` Thank you for choosing us!`;
    if (reviewLink) msg += ` We'd love your feedback: ${reviewLink}`;
    const finalMsg = await appendComplianceFooterIfFirstContact(customer.phone, msg);
    await twilioClient.messages.create({ body: finalMsg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
    if (inv) await supabase.from('invoices').update({ receipt_sent: true }).eq('job_id', req.params.id);
    res.json({ success: true, sent_to: customer.phone });
  } catch(e) {
    console.error('/api/jobs/:id/auto-close-receipt error:', e.message);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

