-- FieldPro CRM — Complete Database Schema
-- Run this ONCE in Supabase SQL Editor on a fresh project


-- ═══════════════════════════════════
-- schema.sql
-- ═══════════════════════════════════

-- FieldPro CRM - Supabase Schema
-- Run this entire file in Supabase SQL Editor

-- USERS (admin + techs)
create table if not exists users (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text unique not null,
  password_hash text not null,
  role text not null default 'tech', -- 'admin' or 'tech'
  phone text,
  color text default '#1e6fff',
  initials text,
  status text default 'offline', -- online, busy, offline
  can_view_all_jobs boolean default false,
  can_edit_jobs boolean default true,
  can_view_finance boolean default false,
  created_at timestamp default now()
);

-- CUSTOMERS
create table if not exists customers (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  phone text not null,
  email text,
  address text,
  notes text,
  created_at timestamp default now()
);

-- JOBS
create table if not exists jobs (
  id text primary key, -- JOB-001 format
  title text not null,
  customer_id uuid references customers(id),
  customer_name text,
  address text,
  tech_id uuid references users(id),
  tech_name text,
  priority text default 'med', -- low, med, high, emergency
  status text default 'new', -- new, assigned, in-progress, done
  notes text,
  invoice_id text,
  job_date date default current_date,
  created_at timestamp default now(),
  updated_at timestamp default now()
);

-- INVOICES
create table if not exists invoices (
  id text primary key,
  job_id text references jobs(id),
  customer_id uuid references customers(id),
  customer_name text,
  tech_id uuid references users(id),
  tech_name text,
  line_items jsonb default '[]',
  subtotal numeric(10,2) default 0,
  tax_rate numeric(5,2) default 8.5,
  tax_amount numeric(10,2) default 0,
  total numeric(10,2) default 0,
  status text default 'unpaid', -- unpaid, paid
  sent_to_customer boolean default false,
  invoice_date date default current_date,
  paid_at timestamp,
  created_at timestamp default now()
);

-- MESSAGES (SMS threads)
create table if not exists messages (
  id uuid default gen_random_uuid() primary key,
  contact_name text not null,
  contact_phone text,
  contact_type text, -- customer, tech
  direction text not null, -- out, in
  body text not null,
  twilio_sid text,
  read boolean default false,
  created_at timestamp default now()
);

-- FORM FIELDS (intake form builder)
create table if not exists form_fields (
  id uuid default gen_random_uuid() primary key,
  label text not null,
  field_type text not null,
  required boolean default false,
  builtin boolean default false,
  options jsonb default '[]',
  sort_order integer default 0,
  created_at timestamp default now()
);

-- SETTINGS
create table if not exists settings (
  key text primary key,
  value text,
  updated_at timestamp default now()
);

-- NOTIFICATIONS
create table if not exists notifications (
  id uuid default gen_random_uuid() primary key,
  type text, -- new_job, new_message, payment, job_done
  title text,
  body text,
  read boolean default false,
  created_at timestamp default now()
);

-- SEED DEFAULT SETTINGS
insert into settings (key, value) values
  ('business_name', 'FieldPro'),
  ('twilio_number', '+12673676484'),
  ('tax_rate', '8.5'),
  ('invoice_prefix', 'INV'),
  ('invoice_footer', 'Thank you for your business!'),
  ('call_mask_enabled', 'true'),
  ('primary_color', '#1e6fff'),
  ('notif_new_job', 'true'),
  ('notif_job_assigned', 'true'),
  ('notif_job_done', 'true'),
  ('notif_sms_reply', 'true'),
  ('notif_payment', 'true')
on conflict (key) do nothing;

-- SEED DEFAULT FORM FIELDS
insert into form_fields (label, field_type, required, builtin, sort_order) values
  ('Full Name', 'text', true, true, 1),
  ('Phone Number', 'phone', true, true, 2),
  ('Service Address', 'text', true, true, 3),
  ('Issue Description', 'textarea', true, true, 4),
  ('Preferred Date', 'date', false, false, 5),
  ('Priority Level', 'select', false, false, 6)
on conflict do nothing;

-- SEED ADMIN USER (password: admin123 — change after first login)
insert into users (name, email, password_hash, role, color, initials, can_view_all_jobs, can_edit_jobs, can_view_finance)
values (
  'Admin',
  'admin@fieldpro.com',
  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- password: password
  'admin',
  '#1e6fff',
  'AD',
  true,
  true,
  true
) on conflict (email) do nothing;

-- Enable Row Level Security
alter table users enable row level security;
alter table customers enable row level security;
alter table jobs enable row level security;
alter table invoices enable row level security;
alter table messages enable row level security;
alter table form_fields enable row level security;
alter table settings enable row level security;
alter table notifications enable row level security;

-- Open policies for anon key (app handles auth via JWT)
create policy "allow all" on users for all using (true) with check (true);
create policy "allow all" on customers for all using (true) with check (true);
create policy "allow all" on jobs for all using (true) with check (true);
create policy "allow all" on invoices for all using (true) with check (true);
create policy "allow all" on messages for all using (true) with check (true);
create policy "allow all" on form_fields for all using (true) with check (true);
create policy "allow all" on settings for all using (true) with check (true);
create policy "allow all" on notifications for all using (true) with check (true);

-- JOB FIELDS (custom fields for new job form)
create table if not exists job_fields (
  id uuid default gen_random_uuid() primary key,
  label text not null,
  field_type text not null,
  required boolean default false,
  builtin boolean default false,
  options jsonb default '[]',
  sort_order integer default 0,
  active boolean default true,
  created_at timestamp default now()
);

alter table job_fields enable row level security;
create policy "allow all" on job_fields for all using (true) with check (true);

-- SEED DEFAULT JOB FIELDS
insert into job_fields (label, field_type, required, builtin, sort_order) values
  ('Job Title', 'text', true, true, 1),
  ('Customer', 'customer_select', true, true, 2),
  ('Service Address', 'text', true, true, 3),
  ('Assign Technician', 'tech_select', false, true, 4),
  ('Priority', 'priority_select', false, true, 5),
  ('Job Date', 'date', false, true, 6),
  ('Notes', 'textarea', false, true, 7)
on conflict do nothing;

-- Update business name to Express Lock&Key
insert into settings (key, value) values ('business_name', 'Express Lock&Key')
on conflict (key) do update set value = 'Express Lock&Key';


-- ═══════════════════════════════════
-- schema_patch2.sql
-- ═══════════════════════════════════

-- PATCH 2 — Ticket system upgrade

-- Add new columns to jobs table
alter table jobs add column if not exists phone text;
alter table jobs add column if not exists job_type text;
alter table jobs add column if not exists car_make_model text;
alter table jobs add column if not exists car_year text;
alter table jobs add column if not exists scheduled_date timestamp;
alter table jobs add column if not exists close_date timestamp;
alter table jobs add column if not exists tags jsonb default '[]';
alter table jobs add column if not exists reminder_sent boolean default false;

-- Add new columns to invoices
alter table invoices add column if not exists parts_cost numeric(10,2) default 0;
alter table invoices add column if not exists labor_cost numeric(10,2) default 0;
alter table invoices add column if not exists tech_commission_type text default 'percentage'; -- percentage or cash
alter table invoices add column if not exists tech_commission_value numeric(10,2) default 0;
alter table invoices add column if not exists tech_commission_amount numeric(10,2) default 0;
alter table invoices add column if not exists receipt_sent boolean default false;

-- TICKET HISTORY (change log)
create table if not exists ticket_history (
  id uuid default gen_random_uuid() primary key,
  job_id text references jobs(id),
  user_id uuid references users(id),
  user_name text,
  action text not null,
  field_changed text,
  old_value text,
  new_value text,
  created_at timestamp default now()
);
alter table ticket_history enable row level security;
create policy "allow all" on ticket_history for all using (true) with check (true);

-- CALL RECORDINGS
create table if not exists call_recordings (
  id uuid default gen_random_uuid() primary key,
  job_id text references jobs(id),
  tech_name text,
  customer_name text,
  call_sid text,
  recording_sid text,
  recording_url text,
  duration integer,
  direction text,
  created_at timestamp default now()
);
alter table call_recordings enable row level security;
create policy "allow all" on call_recordings for all using (true) with check (true);

-- TAGS
create table if not exists tags (
  id uuid default gen_random_uuid() primary key,
  label text not null unique,
  color text default '#1e6fff',
  created_at timestamp default now()
);
alter table tags enable row level security;
create policy "allow all" on tags for all using (true) with check (true);

-- Seed default tags
insert into tags (label, color) values
  ('VIP', '#7c3aed'),
  ('Urgent', '#ef4444'),
  ('Follow Up', '#f59e0b'),
  ('Warranty', '#0891b2'),
  ('Repeat Customer', '#22c55e')
on conflict (label) do nothing;

-- Update Twilio call webhook to support recording
update settings set value = 'true' where key = 'call_recording_enabled';
insert into settings (key, value) values ('call_recording_enabled', 'true') on conflict (key) do nothing;
insert into settings (key, value) values ('tech_default_commission', '30') on conflict (key) do nothing;
insert into settings (key, value) values ('tech_default_commission_type', 'percentage') on conflict (key) do nothing;


-- ═══════════════════════════════════
-- schema_patch3.sql
-- ═══════════════════════════════════

-- PATCH 3 — Booking, Automation, Google Integration

-- BOOKINGS table (customer online submissions)
create table if not exists bookings (
  id uuid default gen_random_uuid() primary key,
  type text not null default 'request', -- 'request' or 'scheduled'
  customer_name text not null,
  phone text not null,
  email text,
  address text,
  job_type text,
  car_make_model text,
  car_year text,
  preferred_date date,
  scheduled_time timestamp,
  notes text,
  status text default 'pending', -- pending, confirmed, converted, cancelled
  job_id text references jobs(id),
  created_at timestamp default now()
);
alter table bookings enable row level security;
create policy "allow all" on bookings for all using (true) with check (true);

-- AUTOMATIONS table
create table if not exists automations (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  active boolean default true,
  trigger_event text not null, -- new_job, status_change, job_assigned, payment_received, new_booking, scheduled_time
  trigger_condition jsonb default '{}', -- e.g. {field: "job_type", operator: "equals", value: "Car Lockout"}
  actions jsonb default '[]', -- array of {type, params}
  run_count integer default 0,
  last_run timestamp,
  created_at timestamp default now()
);
alter table automations enable row level security;
create policy "allow all" on automations for all using (true) with check (true);

-- Seed example automations
insert into automations (name, trigger_event, trigger_condition, actions) values
  ('SMS customer on new booking', 'new_booking', '{}', '[{"type":"send_sms_customer","message":"Hi {customer_name}, we received your booking request for {job_type}. We will confirm shortly. — Express Lock&Key"}]'),
  ('Notify tech when assigned', 'job_assigned', '{}', '[{"type":"send_sms_tech","message":"New job assigned: {job_id} — {job_type} at {address}. Check your CRM for details."}]'),
  ('Send reminder 1hr before', 'scheduled_time', '{"hours_before": 1}', '[{"type":"send_sms_customer","message":"Reminder: Your appointment with Express Lock&Key is in 1 hour at {address}. See you soon!"}]')
on conflict do nothing;

-- Add Google settings
insert into settings (key, value) values
  ('google_maps_api_key', ''),
  ('google_calendar_enabled', 'false'),
  ('google_calendar_id', ''),
  ('google_oauth_client_id', ''),
  ('google_oauth_client_secret', ''),
  ('booking_page_title', 'Book a Service'),
  ('booking_page_subtitle', 'Fast & reliable locksmith services'),
  ('booking_auto_confirm', 'false'),
  ('booking_business_hours_start', '08:00'),
  ('booking_business_hours_end', '20:00')
on conflict (key) do nothing;


-- ═══════════════════════════════════
-- schema_patch4.sql
-- ═══════════════════════════════════

-- PATCH 4: Zapier workflows, AI assistant, editable invoices

-- WORKFLOWS (enhanced automations with scheduling)
create table if not exists workflows (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  description text,
  active boolean default true,
  trigger_type text not null, -- event, schedule, webhook
  trigger_event text, -- new_job, status_change, job_assigned, payment_received, new_booking
  trigger_schedule text, -- cron-like: daily_8am, weekly_monday, hourly
  trigger_condition jsonb default '{}',
  actions jsonb default '[]',
  -- action types: send_sms, send_whatsapp, send_email, create_notification,
  --               update_status, assign_tag, assign_tech, create_job, webhook_post,
  --               send_report, send_reminder
  run_count integer default 0,
  last_run timestamp,
  next_run timestamp,
  created_at timestamp default now()
);
alter table workflows enable row level security;
create policy "allow all" on workflows for all using (true) with check (true);

-- AI ASSISTANT CHAT HISTORY
create table if not exists ai_chat (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id),
  role text not null, -- user, assistant
  content text not null,
  actions_taken jsonb default '[]',
  created_at timestamp default now()
);
alter table ai_chat enable row level security;
create policy "allow all" on ai_chat for all using (true) with check (true);

-- Seed example workflows
insert into workflows (name, description, trigger_type, trigger_event, actions) values
  ('WhatsApp on new booking', 'Send WhatsApp to customer when they book', 'event', 'new_booking',
   '[{"type":"send_whatsapp","to":"customer","message":"Hi {customer_name}! We received your booking for {job_type}. We will confirm shortly. — Express Lock&Key"}]'),
  ('SMS customer when job done', 'Text customer when job is completed', 'event', 'status_change',
   '[{"type":"send_sms","to":"customer","message":"Hi {customer_name}, your job {job_id} is complete! Please dont hesitate to reach out if you need anything. — Express Lock&Key"}]'),
  ('Daily 8am report', 'Send daily job summary every morning', 'schedule', null,
   '[{"type":"send_report","to":"admin","report_type":"daily","message":"Daily Report: {total_jobs} jobs today, {pending} pending, ${revenue} collected."}]'),
  ('Reminder 1hr before appointment', 'WhatsApp customer 1hr before scheduled job', 'event', 'scheduled_time',
   '[{"type":"send_whatsapp","to":"customer","message":"Reminder: Your Express Lock&Key technician is coming in 1 hour to {address}. Reply STOP to cancel."}]')
on conflict do nothing;

-- Add editable flag and edit history to invoices
alter table invoices add column if not exists locked boolean default false;
alter table invoices add column if not exists edit_history jsonb default '[]';
alter table invoices add column if not exists notes text;

-- Make sure jobs can be reopened
alter table jobs add column if not exists reopened_at timestamp;
alter table jobs add column if not exists reopen_reason text;

-- Whatsapp settings
insert into settings (key, value) values
  ('whatsapp_enabled', 'false'),
  ('whatsapp_from', 'whatsapp:+14155238886'),
  ('ai_assistant_enabled', 'true'),
  ('workflow_daily_report_time', '08:00'),
  ('workflow_reminder_hours_before', '1')
on conflict (key) do nothing;

-- Add call_summary to recordings
alter table call_recordings add column if not exists call_summary text;
alter table call_recordings add column if not exists direction text default 'outbound';

-- Custom status labels
insert into settings (key, value) values
  ('custom_status_labels', '["new","assigned","in-progress","done","cancelled"]'),
  ('admin_phone', '')
on conflict (key) do nothing;

-- Add ANTHROPIC_API_KEY reminder (set in Railway variables, not DB)
-- Add workflows table (full version with scheduling)
-- admin_phone for reports
insert into settings (key, value) values ('admin_phone', '') on conflict (key) do nothing;

-- Make sure call_recordings has direction
alter table call_recordings add column if not exists direction text default 'outbound';
alter table call_recordings add column if not exists call_summary text;

-- Per-tech call masking settings
alter table users add column if not exists use_masking boolean default true;
alter table users add column if not exists direct_phone text;

-- Review link setting
insert into settings (key, value) values
  ('review_link', ''),
  ('auto_send_receipt', 'true'),
  ('receipt_include_review', 'true')
on conflict (key) do nothing;

