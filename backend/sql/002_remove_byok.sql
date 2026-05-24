-- Migration 002: Remove BYOK — using platform Anthropic key only
alter table public.users drop column if exists byok_key;
