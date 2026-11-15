-- Run in Supabase SQL Editor. Each authenticated user can access ONLY their own snapshot.
create table if not exists public.app_snapshots (
 user_id uuid primary key references auth.users(id) on delete cascade,
 revision bigint not null default 1,
 payload jsonb not null,
 updated_at timestamptz not null default now()
);
alter table public.app_snapshots enable row level security;
revoke all on public.app_snapshots from anon;
grant select on public.app_snapshots to authenticated;
drop policy if exists "read_own_snapshot" on public.app_snapshots;
create policy "read_own_snapshot" on public.app_snapshots for select to authenticated using (user_id = (select auth.uid()));
-- Writes only through version-checked RPC.
create or replace function public.save_app_snapshot(p_expected_revision bigint,p_payload jsonb)
returns bigint language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := auth.uid(); v_revision bigint;
begin
 if v_uid is null then raise exception 'Not authenticated'; end if;
 if jsonb_typeof(p_payload) <> 'object' then raise exception 'Invalid payload'; end if;
 insert into public.app_snapshots(user_id,revision,payload) values(v_uid,1,p_payload)
 on conflict(user_id) do update set revision=public.app_snapshots.revision+1,payload=excluded.payload,updated_at=now()
 where public.app_snapshots.revision=p_expected_revision
 returning revision into v_revision;
 if v_revision is null then raise exception 'Sync conflict: revision changed'; end if;
 return v_revision;
end;$$;
revoke all on function public.save_app_snapshot(bigint,jsonb) from public,anon;
grant execute on function public.save_app_snapshot(bigint,jsonb) to authenticated;
