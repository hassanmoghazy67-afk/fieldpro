# FieldPro CRM — Complete Deployment Guide
# Express Lock&Key

## STEP 1 — SUPABASE (Database)

1. Go to supabase.com → New Project → name: fieldpro-crm
2. Wait for it to load (~2 min)
3. Go to SQL Editor → New Query
4. Open schema_complete.sql from this folder
5. Copy ALL contents → Paste → Click RUN
6. You should see "Success"
7. Go to Settings → API → copy:
   - Project URL (https://xxxx.supabase.co)
   - anon/public key (long string starting with eyJ...)

## STEP 2 — GITHUB

1. Go to github.com → New Repository → name: fieldpro-crm → Private → Create
2. Click "uploading an existing file"
3. Upload ALL files from this folder INCLUDING the public/ folder:
   - server.js
   - package.json
   - railway.json
   - nixpacks.toml
   - Procfile
   - schema_complete.sql
   - public/index.html
   - public/booking.html
   - public/intake.html

   NOTE: To upload public/index.html properly:
   - Click "Add file" → "Create new file"
   - Type: public/index.html in the name box
   - Paste the contents of public/index.html
   - Commit

## STEP 3 — RAILWAY

1. Go to railway.app → New Project → Deploy from GitHub → select fieldpro-crm
2. Click Variables tab → Add each one:

   SUPABASE_URL          = (your supabase project URL)
   SUPABASE_ANON_KEY     = (your supabase anon key)
   TWILIO_ACCOUNT_SID    = ACed6f0fd963e4246e050db7ff9c199e6b
   TWILIO_AUTH_TOKEN     = (your current twilio auth token from twilio.com)
   TWILIO_PHONE_NUMBER   = +12673676484
   JWT_SECRET            = fieldpro_jwt_secret_expresslockkey_2026
   NODE_ENV              = production
   PORT                  = 3000
   NIXPACKS_NODE_VERSION = 20
   ANTHROPIC_API_KEY     = (from console.anthropic.com → API Keys)

3. Railway builds (~2 min) → generates a URL like:
   https://fieldpro-crm-production.up.railway.app

4. Click Settings → Domains → copy your URL

## STEP 4 — TEST

Open: https://YOUR-URL/api/health
Should show: {"status":"ok","supabase":"connected",...}

If OK, go to your URL and log in:
  Email:    admin@fieldpro.com
  Password: Admin@2026

CHANGE YOUR PASSWORD immediately after first login:
  Admin Settings → Change Password

## STEP 5 — TWILIO WEBHOOK (for incoming SMS)

1. Go to twilio.com → Phone Numbers → your number
2. Messaging → "When a message comes in":
   https://YOUR-URL/api/webhooks/sms
   Method: HTTP POST

3. Voice → "When a call comes in":
   https://YOUR-URL/api/webhooks/voice
   Method: HTTP POST

## SHARING WITH TECHS

Send techs this link to log in:
  https://YOUR-URL

Customer booking page:
  https://YOUR-URL/booking

## MONTHLY COSTS

  Supabase:     Free
  Railway:      Free tier / $5/mo
  Twilio:       ~$1.15/mo + usage
  Total:        ~$5-10/mo
