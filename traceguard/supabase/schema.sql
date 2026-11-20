-- Run in the Supabase SQL editor. Keep the service-role key on the backend only.
create table if not exists public.evaluation_history (
  id uuid primary key,
  created_utc timestamptz not null,
  key_id text not null,
  user_agent text not null default '',
  caller_ip text not null default '',
  verdict text not null check (verdict in ('PASS','QUARANTINE','CRITICAL_CANARY')),
  risk_score integer not null check (risk_score between 0 and 100),
  triggered_rules jsonb not null default '[]'::jsonb,
  canary boolean not null default false,
  payload jsonb not null,
  result jsonb not null
);
create index if not exists evaluation_history_created_idx on public.evaluation_history (created_utc desc);

create table if not exists public.canary_alerts (
  id bigint generated always as identity primary key,
  evaluation_id uuid not null references public.evaluation_history(id),
  created_utc timestamptz not null,
  key_id text not null,
  payload jsonb not null
);

create table if not exists public.validation_metrics (
  id integer primary key check (id = 1),
  true_positives integer not null default 0 check (true_positives >= 0),
  false_positives integer not null default 0 check (false_positives >= 0),
  missed_detections integer not null default 0 check (missed_detections >= 0),
  evidence_row_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  updated_utc timestamptz not null
);

create table if not exists public.evidence_references (
  evidence_id text primary key,
  row_reference text not null default '',
  updated_utc timestamptz not null
);
create table if not exists public.evidence_checklist (
  item_id text primary key,
  checked boolean not null default false,
  updated_utc timestamptz not null
);

alter table public.evaluation_history enable row level security;
alter table public.canary_alerts enable row level security;
alter table public.validation_metrics enable row level security;
alter table public.evidence_references enable row level security;
alter table public.evidence_checklist enable row level security;
-- No browser policies are defined. The backend service key bypasses RLS and is never sent to clients.
