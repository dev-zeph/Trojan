-- Migration 001: Initial schema
-- Run this in Supabase SQL Editor

-- Users table (extends Supabase auth.users)
create table public.users (
  id uuid references auth.users(id) primary key,
  email text not null,
  github_username text,
  stripe_customer_id text,
  subscription_status text not null default 'free',
  subscription_id text,
  created_at timestamptz not null default now()
);

-- AI response cache (avoid redundant Claude API calls)
create table public.ai_cache (
  id uuid primary key default gen_random_uuid(),
  rule_id text not null,
  scanner text not null,
  simply text not null,
  actions jsonb not null,
  created_at timestamptz not null default now(),
  unique(rule_id, scanner)
);

-- Row level security
alter table public.users enable row level security;
alter table public.ai_cache enable row level security;

-- Service role bypasses RLS (our backend uses service role key)
create policy "Service role full access on users"
  on public.users for all using (true);

create policy "Service role full access on ai_cache"
  on public.ai_cache for all using (true);
