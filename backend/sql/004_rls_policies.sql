-- Migration 004: Allow users to update and delete their own row

create policy "Users can update own row"
  on public.users for update
  using (auth.uid() = id);

create policy "Users can delete own row"
  on public.users for delete
  using (auth.uid() = id);
