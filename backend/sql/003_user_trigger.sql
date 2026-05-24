-- Migration 003: Auto-create user row on first login + allow users to read own row

-- Trigger: when a new user signs up via Supabase auth, insert into public.users
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.users (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Policy: allow authenticated users to read their own row
create policy "Users can read own row"
  on public.users for select
  using (auth.uid() = id);
