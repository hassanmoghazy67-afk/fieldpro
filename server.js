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

const app = express();
app.set('trust proxy', 1); // Required for Railway/reverse proxy
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

// ─── AUTH ────────────────────────────────────────────────────────────────────


// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('count').single();
    res.json({ 
      status: 'ok', 
      supabase: error ? 'error: '+error.message : 'connected',
      twilio: process.env.TWILIO_ACCOUNT_SID ? 'configured' : 'missing',
      jwt: process.env.JWT_SECRET ? 'configured' : 'missing'
    });
  } catch(e) {
    res.json({ status: 'error', message: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error) return res.status(500).json({ error: 'Database error: ' + error.message });
    if (!user) return res.status(401).json({ error: 'No account found with that email' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });
    await supabase.from('users').update({ status: 'online' }).eq('id', user.id);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, color: user.color, initials: user.initials } });
  } catch(e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  await supabase.from('users').update({ status: 'offline' }).eq('id', req.user.id);
  res.json({ success: true });
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from('users').update({ password_hash: hash }).eq('id', req.user.id);
  res.json({ success: true });
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('users').select('id,name,email,role,phone,color,initials,status,can_view_all_jobs,can_edit_jobs,can_view_finance,created_at').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const { name, email, password, role, phone, color } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, password required' });
  const hash = await bcrypt.hash(password, 10);
  const initials = name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
  const { data, error } = await supabase.from('users').insert({ name, email, password_hash: hash, role: role || 'tech', phone, color: color || '#1e6fff', initials }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance } = req.body;
  const initials = name ? name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() : undefined;
  const update = { name, role, phone, color, status, can_view_all_jobs, can_edit_jobs, can_view_finance };
  if (initials) update.initials = initials;
  Object.keys(update).forEach(k => update[k] === undefined && delete update[k]);
  const { data, error } = await supabase.from('users').update(update).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─── CUSTOMERS ───────────────────────────────────────────────────────────────

app.get('/api/customers', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('customers').select('*').order('name');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/customers', authMiddleware, async (req, res) => {
  const { name, phone, email, address, notes } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Name and phone required' });
  const { data, error } = await supabase.from('customers').insert({ name, phone, email, address, notes }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await createNotification('new_customer', 'New Customer Added', `${name} was added to customers`);
  res.json(data);
});

app.put('/api/customers/:id', authMiddleware, async (req, res) => {
  const { name, phone, email, address, notes } = req.body;
  const { data, error } = await supabase.from('customers').update({ name, phone, email, address, notes }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/customers/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('customers').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─── JOBS ─────────────────────────────────────────────────────────────────────

app.get('/api/jobs', authMiddleware, async (req, res) => {
  let query = supabase.from('jobs').select('*').order('created_at', { ascending: false });
  if (req.user.role === 'tech' && !req.query.all) query = query.eq('tech_id', req.user.id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/jobs', authMiddleware, async (req, res) => {
  const { title, customer_id, customer_name, address, tech_id, tech_name, priority, status, notes, job_date } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const count = await supabase.from('jobs').select('id', { count: 'exact' });
  const num = String((count.count || 0) + 1).padStart(3, '0');
  const id = `JOB-${num}`;
  const { data, error } = await supabase.from('jobs').insert({ id, title, customer_id, customer_name, address, tech_id, tech_name, priority: priority || 'med', status: status || 'new', notes, job_date }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await createNotification('new_job', 'New Job Created', `${id} — ${title}`);
  // Auto SMS tech if assigned
  if (tech_id && tech_name) {
    const { data: tech } = await supabase.from('users').select('phone').eq('id', tech_id).single();
    if (tech?.phone) {
      try {
        await twilioClient.messages.create({ body: `FieldPro: You've been assigned ${id} — ${title} at ${address || 'TBD'}. Login to view details.`, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone });
      } catch (e) { console.log('SMS error:', e.message); }
    }
    await createNotification('job_assigned', 'Job Assigned', `${id} assigned to ${tech_name}`);
  }
  res.json(data);
});

app.put('/api/jobs/:id', authMiddleware, async (req, res) => {
  const { data: old } = await supabase.from('jobs').select('*').eq('id', req.params.id).single();
  const update = { ...req.body, updated_at: new Date().toISOString() };
  // Mark assignment timestamp + reset confirmation when tech changes
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
  }
  if (update.tech_name && update.tech_name !== old?.tech_name) {
    await logHistory(req.params.id, req.user.id, req.user.name, 'Tech assigned', 'tech_name', old?.tech_name, update.tech_name);
    // SMS the tech right away so the no-response timer is meaningful
    if (update.tech_id) {
      const { data: tech } = await supabase.from('users').select('phone').eq('id', update.tech_id).single();
      if (tech?.phone) {
        try { await twilioClient.messages.create({ body: `FieldPro: You've been assigned ${req.params.id} — ${data.title || data.job_type || ''} at ${data.address || 'TBD'}. Reply OK to confirm.`, from: process.env.TWILIO_PHONE_NUMBER, to: tech.phone }); } catch(e) {}
      }
    }
  }
  res.json(data);
});

// ─── CLOSING TICKET SAFETY CHECK ──────────────────────────────────────────────
// Called by the frontend right before a job is closed, to warn if the tech
// closing it isn't the last tech who was actually active in the job's chat thread.
app.get('/api/jobs/:id/close-check', authMiddleware, async (req, res) => {
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
});

app.delete('/api/jobs/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('jobs').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─── INVOICES ─────────────────────────────────────────────────────────────────

app.get('/api/invoices', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('invoices').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/invoices', authMiddleware, async (req, res) => {
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
});

app.put('/api/invoices/:id/pay', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('invoices').update({ status: 'paid', paid_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await createNotification('payment', 'Payment Received', `Invoice ${req.params.id} marked as paid — $${data.total}`);
  res.json(data);
});

app.post('/api/invoices/:id/send', authMiddleware, async (req, res) => {
  const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  const { data: customer } = await supabase.from('customers').select('phone,email').eq('id', inv.customer_id).single();
  const { data: bizSettings } = await supabase.from('settings').select('key,value');
  const settings = {};
  bizSettings?.forEach(s => settings[s.key] = s.value);
  const msg = `${settings.business_name || 'FieldPro'} Invoice ${inv.id}\nAmount: $${inv.total?.toFixed(2)}\nStatus: ${inv.status}\n${settings.invoice_footer || 'Thank you for your business!'}`;
  if (customer?.phone) {
    try {
      await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ sent_to_customer: true }).eq('id', req.params.id);
      res.json({ success: true, method: 'sms' });
    } catch (e) { res.status(500).json({ error: e.message }); }
  } else { res.status(400).json({ error: 'No customer phone on file' }); }
});

// ─── MESSAGES / SMS ───────────────────────────────────────────────────────────

app.get('/api/messages', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('messages').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/messages/:contact', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('messages').select('*').eq('contact_name', decodeURIComponent(req.params.contact)).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  await supabase.from('messages').update({ read: true }).eq('contact_name', decodeURIComponent(req.params.contact)).eq('direction', 'in');
  res.json(data);
});

app.post('/api/messages/send', authMiddleware, async (req, res) => {
  const { contact_name, contact_phone, contact_type, body } = req.body;
  if (!contact_phone || !body) return res.status(400).json({ error: 'Phone and message required' });
  try {
    const msg = await twilioClient.messages.create({ body, from: process.env.TWILIO_PHONE_NUMBER, to: contact_phone });
    const { data } = await supabase.from('messages').insert({ contact_name, contact_phone, contact_type, direction: 'out', body, twilio_sid: msg.sid, read: true }).select().single();
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
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
  const { From, Body, To } = req.body;
  // Find who sent it
  const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
  const { data: tech } = await supabase.from('users').select('id,name,was_unavailable').eq('phone', From).single();
  const contact_name = customer?.name || tech?.name || From;
  const contact_type = customer ? 'customer' : tech ? 'tech' : 'unknown';
  const bodyTrim = (Body || '').trim();
  const bodyLower = bodyTrim.toLowerCase();

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
      const { data: stillOpen } = await supabase.from('jobs').select('id,title,job_type,status').eq('tech_id', tech.id).in('status', ['assigned', 'in-progress']);
      await createAlert('tech_available', {
        title: `${tech.name} is now available`,
        body: `${tech.name} is now available. Click to assign a job.${stillOpen?.length ? ` They still have ${stillOpen.length} open job(s) to follow up on.` : ''}`,
        tech_id: tech.id, tech_name: tech.name, severity: 'info',
        data: { open_jobs: stillOpen || [] }
      });
    }
  }

  await supabase.from('messages').insert({ contact_name, contact_phone: From, contact_type, direction: 'in', body: Body, read: false, job_id, is_closing_attempt, closing_amount, closing_parts, closing_initials });

  if (is_closing_attempt) {
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
});

// Masked call - initiate via Twilio
app.post('/api/calls/masked', authMiddleware, async (req, res) => {
  const { to_phone, contact_name } = req.body;
  try {
    const call = await twilioClient.calls.create({
      url: `${req.protocol}://${req.get('host')}/api/calls/twiml`,
      to: to_phone,
      from: process.env.TWILIO_PHONE_NUMBER
    });
    res.json({ success: true, call_sid: call.sid, message: `Calling ${contact_name} — they will see ${process.env.TWILIO_PHONE_NUMBER}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/calls/twiml', (req, res) => {
  res.set('Content-Type', 'text/xml');
  res.send('<Response><Say>Connecting your FieldPro masked call. Please hold.</Say><Dial></Dial></Response>');
});

// ─── FORM FIELDS ─────────────────────────────────────────────────────────────

app.get('/api/form-fields', async (req, res) => {
  const { data, error } = await supabase.from('form_fields').select('*').order('sort_order');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/form-fields', authMiddleware, adminOnly, async (req, res) => {
  const { label, field_type, required, options } = req.body;
  const { data: existing } = await supabase.from('form_fields').select('sort_order').order('sort_order', { ascending: false }).limit(1);
  const sort_order = (existing?.[0]?.sort_order || 0) + 1;
  const { data, error } = await supabase.from('form_fields').insert({ label, field_type, required, options: options || [], sort_order }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/form-fields/:id', authMiddleware, adminOnly, async (req, res) => {
  const { label, required, options } = req.body;
  const { data, error } = await supabase.from('form_fields').update({ label, required, options }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/form-fields/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('form_fields').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Public intake form submission
app.post('/api/intake', async (req, res) => {
  const fields = req.body;
  const name = fields['Full Name'] || fields.name || 'Unknown';
  const phone = fields['Phone Number'] || fields.phone || '';
  const address = fields['Service Address'] || fields.address || '';
  const notes = fields['Issue Description'] || fields.notes || '';
  let customer;
  const { data: existing } = await supabase.from('customers').select('*').eq('phone', phone).single();
  if (existing) { customer = existing; }
  else {
    const { data: newC } = await supabase.from('customers').insert({ name, phone, address }).select().single();
    customer = newC;
  }
  const count = await supabase.from('jobs').select('id', { count: 'exact' });
  const num = String((count.count || 0) + 1).padStart(3, '0');
  const id = `JOB-${num}`;
  await supabase.from('jobs').insert({ id, title: `Service Request — ${name}`, customer_id: customer?.id, customer_name: name, address, notes, status: 'new', priority: fields['Priority Level'] ? fields['Priority Level'].toLowerCase() : 'med' });
  await createNotification('new_job', 'New Ticket Submitted', `${name} submitted a service request`);
  res.json({ success: true, job_id: id, message: 'Your ticket has been submitted. We will contact you shortly.' });
});


// ─── JOB FIELDS ───────────────────────────────────────────────────────────────

app.get('/api/job-fields', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('job_fields').select('*').eq('active', true).order('sort_order');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/job-fields', authMiddleware, adminOnly, async (req, res) => {
  const { label, field_type, required, options } = req.body;
  const { data: existing } = await supabase.from('job_fields').select('sort_order').order('sort_order', { ascending: false }).limit(1);
  const sort_order = (existing?.[0]?.sort_order || 0) + 1;
  const { data, error } = await supabase.from('job_fields').insert({ label, field_type, required, options: options || [], sort_order, builtin: false }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/job-fields/:id', authMiddleware, adminOnly, async (req, res) => {
  const { label, required, options, active } = req.body;
  const update = {};
  if (label !== undefined) update.label = label;
  if (required !== undefined) update.required = required;
  if (options !== undefined) update.options = options;
  if (active !== undefined) update.active = active;
  const { data, error } = await supabase.from('job_fields').update(update).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/job-fields/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('job_fields').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ─── SETTINGS ─────────────────────────────────────────────────────────────────

app.get('/api/settings', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('settings').select('*');
  if (error) return res.status(500).json({ error: error.message });
  const obj = {};
  data.forEach(s => obj[s.key] = s.value);
  res.json(obj);
});

app.put('/api/settings', authMiddleware, adminOnly, async (req, res) => {
  const entries = Object.entries(req.body);
  for (const [key, value] of entries) {
    await supabase.from('settings').upsert({ key, value, updated_at: new Date().toISOString() });
  }
  res.json({ success: true });
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('notifications').select('*').order('created_at', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('read', false);
  res.json({ success: true });
});

// ─── REPORTS ──────────────────────────────────────────────────────────────────

app.get('/api/reports/weekly', authMiddleware, async (req, res) => {
  const offset = parseInt(req.query.offset) || 0;
  const d = new Date();
  d.setDate(d.getDate() + offset * 7);
  const day = d.getDay();
  const mon = new Date(d); mon.setDate(d.getDate() - day + 1);
  const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
  const monStr = mon.toISOString().split('T')[0];
  const sunStr = sun.toISOString().split('T')[0];
  const { data: jobs } = await supabase.from('jobs').select('*').gte('job_date', monStr).lte('job_date', sunStr);
  const { data: invoices } = await supabase.from('invoices').select('*').gte('invoice_date', monStr).lte('invoice_date', sunStr);
  const { data: techs } = await supabase.from('users').select('*').eq('role', 'tech');
  const techStats = techs?.map(t => {
    const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
    const tInv = invoices?.filter(i => i.tech_id === t.id && i.status === 'paid') || [];
    const revenue = tInv.reduce((a, i) => a + (i.total || 0), 0);
    return { tech: t, jobs_assigned: tJobs.length, jobs_completed: tJobs.filter(j => j.status === 'done').length, revenue, completion_rate: tJobs.length ? Math.round(tJobs.filter(j => j.status === 'done').length / tJobs.length * 100) : 0 };
  });
  res.json({ week_start: monStr, week_end: sunStr, total_jobs: jobs?.length || 0, completed_jobs: jobs?.filter(j => j.status === 'done').length || 0, total_revenue: invoices?.filter(i => i.status === 'paid').reduce((a, i) => a + (i.total || 0), 0) || 0, outstanding: invoices?.filter(i => i.status === 'unpaid').reduce((a, i) => a + (i.total || 0), 0) || 0, tech_stats: techStats || [] });
});

app.get('/api/reports/export', authMiddleware, async (req, res) => {
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
});

// Helper
async function createNotification(type, title, body) {
  await supabase.from('notifications').insert({ type, title, body });
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
      const { data: unassigned } = await supabase.from('jobs').select('id,title,job_type').eq('status', 'new');
      await createAlert('tech_no_response', {
        title: `${job.tech_name} hasn't confirmed ${job.id}`,
        body: `Warning: job ${job.id} assigned to ${job.tech_name} has not been received or confirmed yet.${unassigned?.length ? ` ${unassigned.length} job(s) still unassigned.` : ''}`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'warning',
        data: { unassigned_jobs: unassigned || [] }
      });
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

  // 3) Appointment reminder — N hours before scheduled time, once
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
        body: `Upcoming appointment: ${job.id} is scheduled for ${new Date(job.scheduled_date).toLocaleString()} with ${job.tech_name || 'unassigned tech'}.`,
        job_id: job.id, tech_id: job.tech_id, tech_name: job.tech_name, severity: 'info'
      });
      await supabase.from('jobs').update({ appointment_reminder_sent: true }).eq('id', job.id);
    }
  }

  // 4) Mark techs "unavailable" if no SMS activity in a while, so the next message
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
  const { data, error } = await supabase.from('alerts').select('*').eq('resolved', false).order('created_at', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/alerts/:id/read', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('alerts').update({ read: true }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/alerts/:id/resolve', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('alerts').update({ resolved: true, read: true }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── CLOSING MESSAGES REVIEW PANEL ─────────────────────────────────────────────
// Every tech message flagged as a closing/charge attempt, joined with job context,
// so admin can see at a glance: was it actually closed? on the right tech? what amount?

app.get('/api/closing-messages', authMiddleware, adminOnly, async (req, res) => {
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
});

app.put('/api/closing-messages/:id/review', authMiddleware, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('messages').update({ closing_reviewed: true }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/closing-messages/:id/amount', authMiddleware, adminOnly, async (req, res) => {
  const { amount } = req.body;
  const { data, error } = await supabase.from('messages').update({ closing_amount: amount }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
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

app.get('/api/jobs/:id/history', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('ticket_history').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── TAGS ────────────────────────────────────────────────────────────────────

app.get('/api/tags', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('tags').select('*').order('label');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/tags', authMiddleware, adminOnly, async (req, res) => {
  const { label, color } = req.body;
  if (!label) return res.status(400).json({ error: 'Label required' });
  const { data, error } = await supabase.from('tags').insert({ label, color: color || '#1e6fff' }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/tags/:id', authMiddleware, adminOnly, async (req, res) => {
  const { error } = await supabase.from('tags').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.put('/api/jobs/:id/tags', authMiddleware, async (req, res) => {
  const { tags } = req.body;
  const { data: old } = await supabase.from('jobs').select('tags').eq('id', req.params.id).single();
  const { data, error } = await supabase.from('jobs').update({ tags, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logHistory(req.params.id, req.user.id, req.user.name, 'Tags updated', 'tags', JSON.stringify(old?.tags), JSON.stringify(tags));
  res.json(data);
});

// ─── CALL RECORDINGS ──────────────────────────────────────────────────────────

app.get('/api/jobs/:id/recordings', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('call_recordings').select('*').eq('job_id', req.params.id).order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Twilio recording callback
app.post('/api/webhooks/recording', async (req, res) => {
  const { CallSid, RecordingSid, RecordingUrl, RecordingDuration, To, From } = req.body;
  const { data: customer } = await supabase.from('customers').select('name').eq('phone', To).single();
  const { data: tech } = await supabase.from('users').select('name').eq('phone', From).single();
  // Try to find associated job
  const { data: jobs } = await supabase.from('jobs').select('id').or(`customer_name.eq.${customer?.name || ''},tech_name.eq.${tech?.name || ''}`).eq('status', 'in-progress').limit(1);
  const job_id = jobs?.[0]?.id || null;
  await supabase.from('call_recordings').insert({
    job_id, tech_name: tech?.name || From, customer_name: customer?.name || To,
    call_sid: CallSid, recording_sid: RecordingSid,
    recording_url: RecordingUrl + '.mp3',
    duration: parseInt(RecordingDuration) || 0
  });
  res.set('Content-Type', 'text/xml');
  res.send('<Response></Response>');
});

// Update masked call to include recording
app.post('/api/calls/masked', authMiddleware, async (req, res) => {
  const { to_phone, contact_name, job_id } = req.body;
  try {
    const call = await twilioClient.calls.create({
      url: `${req.protocol}://${req.get('host')}/api/calls/twiml`,
      to: to_phone,
      from: process.env.TWILIO_PHONE_NUMBER,
      record: true,
      recordingStatusCallback: `${req.protocol}://${req.get('host')}/api/webhooks/recording`,
      recordingStatusCallbackMethod: 'POST'
    });
    if (job_id) {
      await logHistory(job_id, req.user.id, req.user.name, 'Call initiated', 'call', '', `Called ${contact_name}`);
    }
    res.json({ success: true, call_sid: call.sid, message: `Calling ${contact_name} — masked via ${process.env.TWILIO_PHONE_NUMBER}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── INVOICE WITH COMMISSION ──────────────────────────────────────────────────

app.post('/api/invoices/advanced', authMiddleware, async (req, res) => {
  const { job_id, customer_id, customer_name, tech_id, tech_name, line_items, parts_items, tax_rate, tech_commission_type, tech_commission_value } = req.body;
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
  let tech_commission_amount = 0;
  if (tech_commission_type === 'percentage') {
    tech_commission_amount = subtotal * (parseFloat(tech_commission_value) / 100);
  } else {
    tech_commission_amount = parseFloat(tech_commission_value) || 0;
  }
  const { data, error } = await supabase.from('invoices').insert({
    id, job_id, customer_id, customer_name, tech_id, tech_name,
    line_items: all_items, subtotal, tax_rate: tr, tax_amount, total, status: 'unpaid',
    parts_cost, labor_cost, tech_commission_type, tech_commission_value, tech_commission_amount
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  if (job_id) {
    await supabase.from('jobs').update({ invoice_id: id, status: 'done', close_date: new Date().toISOString() }).eq('id', job_id);
    await logHistory(job_id, req.user.id, req.user.name, 'Invoice created', 'invoice_id', '', id);
  }
  res.json(data);
});

// Send receipt
app.post('/api/invoices/:id/receipt', authMiddleware, async (req, res) => {
  const { data: inv } = await supabase.from('invoices').select('*').eq('id', req.params.id).single();
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  const { data: customer } = await supabase.from('customers').select('phone').eq('id', inv.customer_id).single();
  const { data: bizSettings } = await supabase.from('settings').select('key,value');
  const s = {}; bizSettings?.forEach(x => s[x.key] = x.value);
  const msg = `RECEIPT from ${s.business_name || 'Express Lock&Key'}\nInvoice: ${inv.id}\nTotal Paid: $${inv.total?.toFixed(2)}\nThank you for your business!\n${s.invoice_footer || ''}`;
  if (customer?.phone) {
    try {
      await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
      await supabase.from('invoices').update({ receipt_sent: true }).eq('id', req.params.id);
      if (inv.job_id) await logHistory(inv.job_id, req.user.id, req.user.name, 'Receipt sent', 'receipt', '', customer.phone);
      res.json({ success: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
  } else { res.status(400).json({ error: 'No phone on file' }); }
});

// Scheduled job reminders — call this endpoint via a cron or manually
app.post('/api/jobs/send-reminders', authMiddleware, adminOnly, async (req, res) => {
  const now = new Date();
  const in24h = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const { data: jobs } = await supabase.from('jobs').select('*')
    .gte('scheduled_date', now.toISOString())
    .lte('scheduled_date', in24h.toISOString())
    .eq('reminder_sent', false)
    .not('tech_id', 'is', null);
  let sent = 0;
  for (const job of (jobs || [])) {
    const { data: tech } = await supabase.from('users').select('phone,name').eq('id', job.tech_id).single();
    if (tech?.phone) {
      try {
        await twilioClient.messages.create({
          body: `Reminder: You have a job tomorrow — ${job.id} ${job.title} at ${job.address || 'TBD'}. Scheduled: ${new Date(job.scheduled_date).toLocaleString()}`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: tech.phone
        });
        await supabase.from('jobs').update({ reminder_sent: true }).eq('id', job.id);
        sent++;
      } catch(e) { console.log('Reminder SMS error:', e.message); }
    }
  }
  res.json({ success: true, reminders_sent: sent });
});

// Serve frontend
app.get('/booking', (req, res) => res.sendFile(path.join(__dirname, 'public', 'booking.html')));
app.get('/intake', (req, res) => res.sendFile(path.join(__dirname, 'public', 'intake.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FieldPro CRM running on port ${PORT}`);
  startAlertEngine().catch(e => console.error('Alert engine failed to start:', e.message));
});

// ─── BOOKINGS ─────────────────────────────────────────────────────────────────

app.get('/api/bookings', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('bookings').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/bookings/:id/confirm', authMiddleware, async (req, res) => {
  const { tech_id, tech_name, scheduled_time } = req.body;
  const { data: booking } = await supabase.from('bookings').select('*').eq('id', req.params.id).single();
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  // Create job from booking
  const count = await supabase.from('jobs').select('id', { count: 'exact' });
  const num = String((count.count || 0) + 1).padStart(3, '0');
  const jobId = `JOB-${num}`;
  let customer;
  const { data: existing } = await supabase.from('customers').select('*').eq('phone', booking.phone).single();
  if (existing) { customer = existing; }
  else {
    const { data: newC } = await supabase.from('customers').insert({ name: booking.customer_name, phone: booking.phone, email: booking.email, address: booking.address }).select().single();
    customer = newC;
  }
  const { data: job } = await supabase.from('jobs').insert({
    id: jobId, title: booking.job_type || 'Service Request', customer_id: customer?.id,
    customer_name: booking.customer_name, phone: booking.phone, address: booking.address,
    job_type: booking.job_type, car_make_model: booking.car_make_model, car_year: booking.car_year,
    tech_id: tech_id || null, tech_name: tech_name || null,
    scheduled_date: scheduled_time || booking.scheduled_time,
    status: tech_id ? 'assigned' : 'new', priority: 'med', notes: booking.notes,
    job_date: new Date().toISOString().split('T')[0]
  }).select().single();
  await supabase.from('bookings').update({ status: 'confirmed', job_id: jobId }).eq('id', req.params.id);
  await createNotification('booking_confirmed', 'Booking Confirmed', `${booking.customer_name} — ${booking.job_type}`);
  // SMS customer confirmation
  try {
    const { data: s } = await supabase.from('settings').select('value').eq('key', 'business_name').single();
    await twilioClient.messages.create({
      body: `Your booking with ${s?.value || 'Express Lock&Key'} is confirmed! Job #${jobId}. We'll be in touch shortly.`,
      from: process.env.TWILIO_PHONE_NUMBER, to: booking.phone
    });
  } catch(e) { console.log('SMS error:', e.message); }
  res.json({ success: true, job_id: jobId, job });
});

app.put('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  await supabase.from('bookings').update({ status: 'cancelled' }).eq('id', req.params.id);
  res.json({ success: true });
});

// Public booking submission
app.post('/api/book', async (req, res) => {
  const { type, customer_name, phone, email, address, job_type, car_make_model, car_year, preferred_date, scheduled_time, notes } = req.body;
  if (!customer_name || !phone) return res.status(400).json({ error: 'Name and phone required' });
  const { data, error } = await supabase.from('bookings').insert({
    type: type || 'request', customer_name, phone, email, address, job_type,
    car_make_model, car_year, preferred_date, scheduled_time, notes
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await createNotification('new_booking', `New ${type === 'scheduled' ? 'Appointment' : 'Service Request'}`, `${customer_name} — ${job_type || 'Service Request'}`);
  // Auto SMS customer acknowledgement
  try {
    const { data: s } = await supabase.from('settings').select('key,value');
    const settings = {}; s?.forEach(x => settings[x.key] = x.value);
    const autoConfirm = settings.booking_auto_confirm === 'true';
    await twilioClient.messages.create({
      body: `Hi ${customer_name}, ${autoConfirm ? 'your booking is confirmed!' : 'we received your request and will confirm shortly.'} — ${settings.business_name || 'Express Lock&Key'}`,
      from: process.env.TWILIO_PHONE_NUMBER, to: phone
    });
  } catch(e) { console.log('SMS error:', e.message); }
  res.json({ success: true, booking_id: data.id });
});

// ─── AUTOMATIONS ──────────────────────────────────────────────────────────────

app.get('/api/automations', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('automations').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/automations', authMiddleware, adminOnly, async (req, res) => {
  const { name, trigger_event, trigger_condition, actions } = req.body;
  const { data, error } = await supabase.from('automations').insert({ name, trigger_event, trigger_condition, actions }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/automations/:id', authMiddleware, adminOnly, async (req, res) => {
  const { name, active, trigger_event, trigger_condition, actions } = req.body;
  const { data, error } = await supabase.from('automations').update({ name, active, trigger_event, trigger_condition, actions }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/automations/:id', authMiddleware, adminOnly, async (req, res) => {
  await supabase.from('automations').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// Run automations engine
async function runAutomations(triggerEvent, jobData) {
  try {
    const { data: automations } = await supabase.from('automations').select('*').eq('trigger_event', triggerEvent).eq('active', true);
    for (const auto of (automations || [])) {
      const cond = auto.trigger_condition || {};
      // Check condition
      if (cond.field && cond.value) {
        const jobVal = jobData[cond.field];
        if (cond.operator === 'equals' && jobVal !== cond.value) continue;
        if (cond.operator === 'contains' && !String(jobVal).includes(cond.value)) continue;
      }
      // Run actions
      for (const action of (auto.actions || [])) {
        try {
          const msg = (action.message || '').replace(/{(\w+)}/g, (_, k) => jobData[k] || '');
          if (action.type === 'send_sms_customer' && jobData.phone) {
            await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: jobData.phone });
          } else if (action.type === 'send_sms_tech' && jobData.tech_phone) {
            await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: jobData.tech_phone });
          } else if (action.type === 'create_notification') {
            await createNotification('automation', auto.name, msg);
          } else if (action.type === 'update_status') {
            await supabase.from('jobs').update({ status: action.status }).eq('id', jobData.id);
          } else if (action.type === 'assign_tag') {
            const { data: j } = await supabase.from('jobs').select('tags').eq('id', jobData.id).single();
            const tags = [...(j?.tags || [])]; if (!tags.includes(action.tag)) tags.push(action.tag);
            await supabase.from('jobs').update({ tags }).eq('id', jobData.id);
          }
        } catch(e) { console.log('Automation action error:', e.message); }
      }
      await supabase.from('automations').update({ run_count: (auto.run_count||0)+1, last_run: new Date().toISOString() }).eq('id', auto.id);
    }
  } catch(e) { console.log('Automation engine error:', e.message); }
}


// ─── WORKFLOWS (Zapier-style) ─────────────────────────────────────────────────

app.get('/api/workflows', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('workflows').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/workflows', authMiddleware, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('workflows').insert(req.body).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  const { data, error } = await supabase.from('workflows').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/workflows/:id', authMiddleware, adminOnly, async (req, res) => {
  await supabase.from('workflows').delete().eq('id', req.params.id);
  res.json({ success: true });
});

app.post('/api/workflows/:id/test', authMiddleware, adminOnly, async (req, res) => {
  const { data: wf } = await supabase.from('workflows').select('*').eq('id', req.params.id).single();
  if (!wf) return res.status(404).json({ error: 'Not found' });
  const testData = { customer_name: 'Test Customer', job_id: 'JOB-001', job_type: 'Car Lockout', address: '123 Test St', tech_name: 'Test Tech', phone: req.body.test_phone || '', revenue: '0', total_jobs: '1', pending: '0' };
  const result = await executeWorkflowActions(wf.actions, testData);
  await supabase.from('workflows').update({ run_count: (wf.run_count||0)+1, last_run: new Date().toISOString() }).eq('id', req.params.id);
  res.json({ success: true, result });
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
  const today = new Date().toISOString().split('T')[0];
  const { data: jobs } = await supabase.from('jobs').select('*').eq('job_date', today);
  const { data: invoices } = await supabase.from('invoices').select('*').eq('invoice_date', today).eq('status', 'paid');
  const revenue = invoices?.reduce((a, i) => a + (i.total || 0), 0) || 0;
  return { total: jobs?.length || 0, pending: jobs?.filter(j => j.status === 'new').length || 0, revenue: revenue.toFixed(2) };
}

// Scheduled workflow runner (call this endpoint via cron or external scheduler)
app.post('/api/workflows/run-scheduled', async (req, res) => {
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
});

function checkSchedule(schedule, now, lastRun) {
  if (!schedule) return false;
  const last = lastRun ? new Date(lastRun) : new Date(0);
  const hoursSinceLast = (now - last) / (1000 * 60 * 60);
  if (schedule === 'hourly') return hoursSinceLast >= 1;
  if (schedule === 'daily_8am') return now.getHours() === 8 && hoursSinceLast >= 23;
  if (schedule === 'daily_6pm') return now.getHours() === 18 && hoursSinceLast >= 23;
  if (schedule === 'weekly_monday') return now.getDay() === 1 && hoursSinceLast >= 167;
  return false;
}

// ─── AI ASSISTANT ─────────────────────────────────────────────────────────────

app.get('/api/ai-chat', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/ai-chat/clear', authMiddleware, async (req, res) => {
  await supabase.from('ai_chat').delete().eq('user_id', req.user.id);
  res.json({ success: true });
});

app.post('/api/ai-assistant', authMiddleware, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  // Gather CRM context
  const [{ data: jobs }, { data: customers }, { data: techs }, { data: invoices }, { data: history }] = await Promise.all([
    supabase.from('jobs').select('*').order('created_at', { ascending: false }).limit(50),
    supabase.from('customers').select('*').limit(30),
    supabase.from('users').select('id,name,role,status,color,initials').eq('role', 'tech'),
    supabase.from('invoices').select('*').order('created_at', { ascending: false }).limit(30),
    supabase.from('ai_chat').select('*').eq('user_id', req.user.id).order('created_at').limit(10)
  ]);

  const today = new Date().toISOString().split('T')[0];
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

  try {
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
      match[2].split(' ').forEach(p => { const [k, ...v] = p.split('='); if (k) params[k] = v.join('='); });
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
    edit_history: editHistory
  }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Reopen a closed job
app.put('/api/jobs/:id/reopen', authMiddleware, adminOnly, async (req, res) => {
  const { reason } = req.body;
  const { data, error } = await supabase.from('jobs').update({ status: 'in-progress', reopened_at: new Date().toISOString(), reopen_reason: reason || 'Reopened by admin', close_date: null }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await logHistory(req.params.id, req.user.id, req.user.name, 'Job reopened', 'status', 'done', 'in-progress');
  res.json(data);
});


// ─── CUSTOM STATUS LABELS ─────────────────────────────────────────────────────
app.get('/api/status-labels', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('settings').select('value').eq('key', 'custom_status_labels').single();
  const labels = data?.value ? JSON.parse(data.value) : ['new','assigned','in-progress','done','cancelled'];
  res.json(labels);
});

app.put('/api/status-labels', authMiddleware, adminOnly, async (req, res) => {
  const { labels } = req.body;
  await supabase.from('settings').upsert({ key: 'custom_status_labels', value: JSON.stringify(labels) });
  res.json({ success: true, labels });
});

// ─── DASHBOARD ANALYTICS ──────────────────────────────────────────────────────
app.get('/api/analytics/dashboard', authMiddleware, async (req, res) => {
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const weekStart = new Date(now); weekStart.setDate(now.getDate() - now.getDay());
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const isAdmin = req.user.role === 'admin';

  const [{ data: jobs }, { data: invoices }, { data: techs }] = await Promise.all([
    supabase.from('jobs').select('*').order('created_at', { ascending: false }),
    isAdmin ? supabase.from('invoices').select('*') : { data: [] },
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

  // Tech performance
  const techPerf = (techs || []).map(t => {
    const tJobs = jobs?.filter(j => j.tech_id === t.id) || [];
    const tInvoices = isAdmin ? (invoices?.filter(i => i.tech_id === t.id && i.status === 'paid') || []) : [];
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
    const d = new Date(now); d.setDate(now.getDate() - i);
    const ds = d.toISOString().split('T')[0];
    const dayJobs = jobs?.filter(j => j.job_date === ds) || [];
    last7.push({ date: ds, label: d.toLocaleDateString('en-US',{weekday:'short'}), total: dayJobs.length, done: dayJobs.filter(j=>j.status==='done').length, cancelled: dayJobs.filter(j=>j.status==='cancelled').length });
  }

  // Revenue (admin only)
  const revenueData = isAdmin ? {
    today: invoices?.filter(i=>i.invoice_date===today&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
    week: invoices?.filter(i=>new Date(i.invoice_date)>=weekStart&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
    month: invoices?.filter(i=>new Date(i.invoice_date)>=monthStart&&i.status==='paid').reduce((a,i)=>a+(i.total||0),0) || 0,
    outstanding: invoices?.filter(i=>i.status==='unpaid').reduce((a,i)=>a+(i.total||0),0) || 0
  } : null;

  res.json({ today: todayJobs, todayTotal: todayJobs.length, weekTotal: weekJobs.length, monthTotal: monthJobs.length, statusCounts, typeCounts, techPerf, last7, revenue: revenueData, totalJobs: jobs?.length || 0, cancelled: statusCounts['cancelled'] || 0 });
});

// ─── DAILY JOB BOARD ──────────────────────────────────────────────────────────
app.get('/api/jobs/daily-board', authMiddleware, async (req, res) => {
  const date = req.query.date || new Date().toISOString().split('T')[0];
  let query = supabase.from('jobs').select('*').eq('job_date', date).order('created_at');
  if (req.user.role !== 'admin') query = query.eq('tech_id', req.user.id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─── CALL MASKING — INBOUND ROUTING ──────────────────────────────────────────
// When customer calls back the masked number, route to the tech
app.post('/api/webhooks/voice', async (req, res) => {
  const { From, To, CallSid } = req.body;
  // Check if caller is a known customer — if so, find their tech
  const { data: customer } = await supabase.from('customers').select('name').eq('phone', From).single();
  let techPhone = null;
  if (customer) {
    // Find most recent active job for this customer
    const { data: job } = await supabase.from('jobs').select('tech_id').eq('customer_name', customer.name).in('status',['assigned','in-progress']).order('created_at',{ascending:false}).limit(1).single();
    if (job?.tech_id) {
      const { data: tech } = await supabase.from('users').select('phone,name').eq('id', job.tech_id).single();
      techPhone = tech?.phone;
      // Create notification
      await createNotification('inbound_call', `Inbound call from ${customer.name}`, `Customer calling back — routing to ${tech?.name || 'tech'}`);
    }
  }
  res.set('Content-Type', 'text/xml');
  if (techPhone) {
    res.send(`<Response><Say>Please hold while we connect you.</Say><Dial record="true" recordingStatusCallback="/api/webhooks/recording"><Number>${techPhone}</Number></Dial></Response>`);
  } else {
    res.send(`<Response><Say>Thank you for calling Express Lock and Key. Please hold while we connect you to our team.</Say><Dial record="true" recordingStatusCallback="/api/webhooks/recording"><Number>${process.env.TWILIO_PHONE_NUMBER}</Number></Dial></Response>`);
  }
  // Log call
  await supabase.from('call_recordings').insert({ tech_name: 'Inbound', customer_name: customer?.name || From, call_sid: CallSid, direction: 'inbound' }).catch(()=>{});
});

// ─── AI CALL SUMMARY ──────────────────────────────────────────────────────────
app.post('/api/recordings/:id/summarize', authMiddleware, async (req, res) => {
  const { data: rec } = await supabase.from('call_recordings').select('*').eq('id', req.params.id).single();
  if (!rec) return res.status(404).json({ error: 'Recording not found' });
  // Generate AI summary using Anthropic
  try {
    const prompt = `You are summarizing a call recording for a locksmith business (Express Lock&Key).
Call details:
- Tech: ${rec.tech_name || 'Unknown'}
- Customer: ${rec.customer_name || 'Unknown'}
- Duration: ${rec.duration || 0} seconds
- Direction: ${rec.direction || 'outbound'}
- Recording URL: ${rec.recording_url || 'not available'}

Based on these details, generate a professional call summary including:
1. Call Overview (who called whom, duration)
2. Likely Purpose (based on job context)
3. Follow-up Actions Recommended
4. Any flags or notes

Keep it concise and professional.`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY || '', 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await aiRes.json();
    const summary = aiData.content?.[0]?.text || 'Summary unavailable';
    await supabase.from('call_recordings').update({ call_summary: summary }).eq('id', req.params.id);
    res.json({ summary });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ─── DUPLICATE CHECK ──────────────────────────────────────────────────────────
app.post('/api/jobs/check-duplicate', authMiddleware, async (req, res) => {
  const { phone, address, job_type } = req.body;
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  let query = supabase.from('jobs').select('id,title,status,customer_name,address,phone,created_at').gte('created_at', cutoff).neq('status', 'cancelled');
  const { data: jobs } = await query;
  const dupes = (jobs || []).filter(j => {
    if (phone && j.phone) {
      const normalizePhone = p => p.replace(/\D/g, '');
      if (normalizePhone(j.phone) === normalizePhone(phone)) return true;
    }
    if (address && j.address && address.length > 5) {
      const norm = s => s.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (norm(j.address).includes(norm(address.slice(0, 8)))) return true;
    }
    return false;
  });
  res.json({ duplicates: dupes, count: dupes.length });
});

// ─── WORKFLOWS TABLE MIGRATION ────────────────────────────────────────────────
// Fix existing automations table — workflows is the new table
// Both exist side by side


// ─── TECH CALL MASKING SETTINGS ───────────────────────────────────────────────

app.put('/api/users/:id/call-settings', authMiddleware, adminOnly, async (req, res) => {
  const { use_masking, direct_phone } = req.body;
  const { data, error } = await supabase.from('users')
    .update({ use_masking: use_masking !== undefined ? use_masking : true, direct_phone: direct_phone || null })
    .eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Updated masked call — respects per-tech masking setting
app.post('/api/calls/masked/v2', authMiddleware, async (req, res) => {
  const { to_name, to_phone, job_id, contact_type } = req.body;
  if (!to_phone) return res.status(400).json({ error: 'Phone required' });
  try {
    // Check if this tech has masking enabled
    let useMasking = true;
    if (contact_type === 'tech') {
      const { data: tech } = await supabase.from('users').select('use_masking,direct_phone').eq('name', to_name).single();
      if (tech && tech.use_masking === false) {
        useMasking = false;
        // Just return the direct number — no Twilio call
        return res.json({ success: true, masking: false, direct_phone: tech.direct_phone || to_phone, message: `Call ${to_name} directly at ${tech.direct_phone || to_phone}` });
      }
    }
    const call = await twilioClient.calls.create({
      url: `${req.protocol}://${req.get('host')}/api/calls/twiml`,
      to: to_phone,
      from: process.env.TWILIO_PHONE_NUMBER,
      record: true,
      recordingStatusCallback: `${req.protocol}://${req.get('host')}/api/webhooks/recording`,
      recordingStatusCallbackMethod: 'POST'
    });
    if (job_id) await logHistory(job_id, req.user.id, req.user.name, 'Masked call initiated', 'call', '', `Called ${to_name}`);
    await createNotification('call', `Call to ${to_name}`, `Masked call initiated via ${process.env.TWILIO_PHONE_NUMBER}`);
    res.json({ success: true, masking: true, call_sid: call.sid, message: `Calling ${to_name} via masked number` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── AUTO RECEIPT + REVIEW LINK ───────────────────────────────────────────────

app.post('/api/jobs/:id/auto-close-receipt', authMiddleware, async (req, res) => {
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
  if (inv) msg += ` Total: $${inv.total?.toFixed(2)}.`;
  msg += ` Thank you for choosing us!`;
  if (reviewLink) msg += ` We'd love your feedback: ${reviewLink}`;
  try {
    await twilioClient.messages.create({ body: msg, from: process.env.TWILIO_PHONE_NUMBER, to: customer.phone });
    await supabase.from('invoices').update({ receipt_sent: true }).eq('job_id', req.params.id);
    res.json({ success: true, sent_to: customer.phone });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

