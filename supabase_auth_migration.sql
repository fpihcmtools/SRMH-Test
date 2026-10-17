-- Link application accounts to Supabase Auth identities.
-- Run this migration in the Supabase SQL Editor before deploying the updated UI.
begin;

alter table public.accounts
    add column if not exists auth_user_id uuid
    references auth.users (id) on delete set null;

create unique index if not exists accounts_auth_user_id_uidx
    on public.accounts (auth_user_id)
    where auth_user_id is not null;

create or replace function public.srmh_is_active_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.accounts
        where auth_user_id = auth.uid()
          and is_active = true
          and lower(raw_role) = 'admin'
    );
$$;

revoke all on function public.srmh_is_active_admin() from public, anon;
grant execute on function public.srmh_is_active_admin() to authenticated;

alter table public.accounts enable row level security;
revoke all on public.accounts from public, anon, authenticated;
grant select, insert, update on public.accounts to authenticated;

drop policy if exists "srmh_accounts_select_linked_or_admin" on public.accounts;
create policy "srmh_accounts_select_linked_or_admin"
    on public.accounts
    for select
    to authenticated
    using (auth_user_id = (select auth.uid()) or (select public.srmh_is_active_admin()));

drop policy if exists "srmh_accounts_select_restrict" on public.accounts;
create policy "srmh_accounts_select_restrict"
    on public.accounts
    as restrictive
    for select
    to authenticated
    using (auth_user_id = (select auth.uid()) or (select public.srmh_is_active_admin()));

drop policy if exists "srmh_accounts_insert_admin" on public.accounts;
create policy "srmh_accounts_insert_admin"
    on public.accounts
    for insert
    to authenticated
    with check ((select public.srmh_is_active_admin()));

drop policy if exists "srmh_accounts_insert_restrict" on public.accounts;
create policy "srmh_accounts_insert_restrict"
    on public.accounts
    as restrictive
    for insert
    to authenticated
    with check ((select public.srmh_is_active_admin()));

drop policy if exists "srmh_accounts_update_admin" on public.accounts;
create policy "srmh_accounts_update_admin"
    on public.accounts
    for update
    to authenticated
    using ((select public.srmh_is_active_admin()))
    with check ((select public.srmh_is_active_admin()));

drop policy if exists "srmh_accounts_update_restrict" on public.accounts;
create policy "srmh_accounts_update_restrict"
    on public.accounts
    as restrictive
    for update
    to authenticated
    using ((select public.srmh_is_active_admin()))
    with check ((select public.srmh_is_active_admin()));

-- Provision each user in Supabase Auth (do not enable public sign-ups), then link
-- its Auth UUID to the existing application account as an administrator:
-- update public.accounts
-- set auth_user_id = '<AUTH_USER_UUID>'
-- where code = '<EXISTING_ACCOUNT_CODE>';

-- Shared authorization helpers. SECURITY DEFINER lets these helpers inspect
-- the linked account without exposing other account rows through RLS.
create or replace function public.srmh_is_active_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.accounts
        where auth_user_id = (select auth.uid())
          and is_active = true
    );
$$;

create or replace function public.srmh_current_account_code()
returns text
language sql
stable
security definer
set search_path = ''
as $$
    select code
    from public.accounts
    where auth_user_id = (select auth.uid())
      and is_active = true
    limit 1;
$$;

create or replace function public.srmh_is_active_ctsv_or_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.accounts
        where auth_user_id = (select auth.uid())
          and is_active = true
          and lower(raw_role) in ('ctsv', 'admin')
    );
$$;

create or replace function public.srmh_feedback_author_matches(
    p_code text,
    p_name text,
    p_role text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.accounts
        where auth_user_id = (select auth.uid())
          and is_active = true
          and code = p_code
          and name = p_name
          and lower(raw_role) = lower(p_role)
    );
$$;

create or replace function public.srmh_can_assign_class_author(p_code text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.accounts actor
        where actor.auth_user_id = (select auth.uid())
          and actor.is_active = true
          and (
              actor.code = p_code
              or lower(actor.raw_role) in ('admin', 'ctsv', 'cnbm')
          )
    )
    and exists (
        select 1
        from public.accounts target
        where target.code = p_code
          and target.is_active = true
    );
$$;

revoke all on function public.srmh_is_active_user() from public, anon;
revoke all on function public.srmh_current_account_code() from public, anon;
revoke all on function public.srmh_is_active_ctsv_or_admin() from public, anon;
revoke all on function public.srmh_feedback_author_matches(text, text, text) from public, anon;
revoke all on function public.srmh_can_assign_class_author(text) from public, anon;
grant execute on function public.srmh_is_active_user() to authenticated;
grant execute on function public.srmh_current_account_code() to authenticated;
grant execute on function public.srmh_is_active_ctsv_or_admin() to authenticated;
grant execute on function public.srmh_feedback_author_matches(text, text, text) to authenticated;
grant execute on function public.srmh_can_assign_class_author(text) to authenticated;

-- Student records: any active linked account may read; inserts/status changes
-- are available to active users, while deletion remains administrator-only.
alter table public.students enable row level security;
revoke all on public.students from public, anon, authenticated;
grant select, insert (mssv, ho_ten, status), update (status, updated_at), delete
    on public.students to authenticated;

drop policy if exists "srmh_students_select_active" on public.students;
create policy "srmh_students_select_active"
    on public.students for select to authenticated
    using ((select public.srmh_is_active_user()));
drop policy if exists "srmh_students_select_restrict" on public.students;
create policy "srmh_students_select_restrict"
    on public.students as restrictive for select to authenticated
    using ((select public.srmh_is_active_user()));

drop policy if exists "srmh_students_insert_active" on public.students;
create policy "srmh_students_insert_active"
    on public.students for insert to authenticated
    with check ((select public.srmh_is_active_user()));
drop policy if exists "srmh_students_insert_restrict" on public.students;
create policy "srmh_students_insert_restrict"
    on public.students as restrictive for insert to authenticated
    with check ((select public.srmh_is_active_user()));

drop policy if exists "srmh_students_update_active" on public.students;
create policy "srmh_students_update_active"
    on public.students for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));
drop policy if exists "srmh_students_update_restrict" on public.students;
create policy "srmh_students_update_restrict"
    on public.students as restrictive for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));

drop policy if exists "srmh_students_delete_admin" on public.students;
create policy "srmh_students_delete_admin"
    on public.students for delete to authenticated
    using ((select public.srmh_is_active_admin()));
drop policy if exists "srmh_students_delete_restrict" on public.students;
create policy "srmh_students_delete_restrict"
    on public.students as restrictive for delete to authenticated
    using ((select public.srmh_is_active_admin()));

-- Feedback: active accounts may read; inserts must identify the signed-in
-- account. A trigger protects feedback content while permitting own reactions.
create or replace function public.srmh_guard_feedback_update()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    current_code text;
begin
    if not (select public.srmh_is_active_user()) then
        raise exception 'An active linked account is required';
    end if;

    current_code := (select public.srmh_current_account_code());

    if old.content is distinct from new.content
       and old.author_code is distinct from current_code
       and not (select public.srmh_is_active_ctsv_or_admin()) then
        raise exception 'Only the feedback author, CTSV, or Admin may edit feedback content';
    end if;

    if old.reactions is distinct from new.reactions then
        if exists (
            select 1
            from jsonb_array_elements(
                coalesce(nullif(to_jsonb(old)->'reactions', 'null'::jsonb), '[]'::jsonb)
            ) as old_reaction(value)
            where old_reaction.value->>'code' is distinct from current_code
              and not (
                  coalesce(nullif(to_jsonb(new)->'reactions', 'null'::jsonb), '[]'::jsonb)
                  @> jsonb_build_array(old_reaction.value)
              )
        ) or exists (
            select 1
            from jsonb_array_elements(
                coalesce(nullif(to_jsonb(new)->'reactions', 'null'::jsonb), '[]'::jsonb)
            ) as new_reaction(value)
            where new_reaction.value->>'code' is distinct from current_code
              and not (
                  coalesce(nullif(to_jsonb(old)->'reactions', 'null'::jsonb), '[]'::jsonb)
                  @> jsonb_build_array(new_reaction.value)
              )
        ) then
            raise exception 'Users may only change their own reactions';
        end if;
    end if;

    return new;
end;
$$;

revoke all on function public.srmh_guard_feedback_update() from public, anon, authenticated;

drop trigger if exists srmh_feedback_update_guard on public.feedbacks;
create trigger srmh_feedback_update_guard
    before update on public.feedbacks
    for each row execute function public.srmh_guard_feedback_update();

alter table public.feedbacks enable row level security;
revoke all on public.feedbacks from public, anon, authenticated;
grant select,
    insert (student_id, role, author_name, author_code, content, parent_id, reactions),
    update (content, reactions),
    delete
    on public.feedbacks to authenticated;

drop policy if exists "srmh_feedbacks_select_active" on public.feedbacks;
create policy "srmh_feedbacks_select_active"
    on public.feedbacks for select to authenticated
    using ((select public.srmh_is_active_user()));
drop policy if exists "srmh_feedbacks_select_restrict" on public.feedbacks;
create policy "srmh_feedbacks_select_restrict"
    on public.feedbacks as restrictive for select to authenticated
    using ((select public.srmh_is_active_user()));

drop policy if exists "srmh_feedbacks_insert_author" on public.feedbacks;
create policy "srmh_feedbacks_insert_author"
    on public.feedbacks for insert to authenticated
    with check (
        (select public.srmh_feedback_author_matches(author_code, author_name, role))
    );
drop policy if exists "srmh_feedbacks_insert_restrict" on public.feedbacks;
create policy "srmh_feedbacks_insert_restrict"
    on public.feedbacks as restrictive for insert to authenticated
    with check (
        (select public.srmh_feedback_author_matches(author_code, author_name, role))
    );

drop policy if exists "srmh_feedbacks_update_active" on public.feedbacks;
create policy "srmh_feedbacks_update_active"
    on public.feedbacks for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));
drop policy if exists "srmh_feedbacks_update_restrict" on public.feedbacks;
create policy "srmh_feedbacks_update_restrict"
    on public.feedbacks as restrictive for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));

drop policy if exists "srmh_feedbacks_delete_admin" on public.feedbacks;
create policy "srmh_feedbacks_delete_admin"
    on public.feedbacks for delete to authenticated
    using ((select public.srmh_is_active_admin()));
drop policy if exists "srmh_feedbacks_delete_restrict" on public.feedbacks;
create policy "srmh_feedbacks_delete_restrict"
    on public.feedbacks as restrictive for delete to authenticated
    using ((select public.srmh_is_active_admin()));

-- Class assignments: active users may read; only active account owners or
-- Admin/CTSV/CNBM may assign an active account as the author.
alter table public.student_classes enable row level security;
revoke all on public.student_classes from public, anon, authenticated;
grant select, insert (student_id, author_code, class_name), delete
    on public.student_classes to authenticated;

drop policy if exists "srmh_student_classes_select_active" on public.student_classes;
create policy "srmh_student_classes_select_active"
    on public.student_classes for select to authenticated
    using ((select public.srmh_is_active_user()));
drop policy if exists "srmh_student_classes_select_restrict" on public.student_classes;
create policy "srmh_student_classes_select_restrict"
    on public.student_classes as restrictive for select to authenticated
    using ((select public.srmh_is_active_user()));

drop policy if exists "srmh_student_classes_insert_authorized" on public.student_classes;
create policy "srmh_student_classes_insert_authorized"
    on public.student_classes for insert to authenticated
    with check ((select public.srmh_can_assign_class_author(author_code)));
drop policy if exists "srmh_student_classes_insert_restrict" on public.student_classes;
create policy "srmh_student_classes_insert_restrict"
    on public.student_classes as restrictive for insert to authenticated
    with check ((select public.srmh_can_assign_class_author(author_code)));

drop policy if exists "srmh_student_classes_delete_admin" on public.student_classes;
create policy "srmh_student_classes_delete_admin"
    on public.student_classes for delete to authenticated
    using ((select public.srmh_is_active_admin()));
drop policy if exists "srmh_student_classes_delete_restrict" on public.student_classes;
create policy "srmh_student_classes_delete_restrict"
    on public.student_classes as restrictive for delete to authenticated
    using ((select public.srmh_is_active_admin()));

-- Roster: active accounts may read and update the escalation preview fields;
-- roster imports and changes to student/class/major assignments are admin-only.
create or replace function public.srmh_guard_roster_write()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not (select public.srmh_is_active_user()) then
        raise exception 'An active linked account is required';
    end if;

    if not (select public.srmh_is_active_admin()) then
        if tg_op = 'INSERT' then
            raise exception 'Only Admin may add roster rows';
        end if;
        if (to_jsonb(new) - array['latestFb', 'latestFbContent'])
           is distinct from
           (to_jsonb(old) - array['latestFb', 'latestFbContent']) then
            raise exception 'Only Admin may change roster assignments';
        end if;
    end if;

    return new;
end;
$$;

revoke all on function public.srmh_guard_roster_write() from public, anon, authenticated;

drop trigger if exists srmh_roster_write_guard on public.student_roster;
create trigger srmh_roster_write_guard
    before insert or update on public.student_roster
    for each row execute function public.srmh_guard_roster_write();

alter table public.student_roster enable row level security;
revoke all on public.student_roster from public, anon, authenticated;
grant select, insert, update on public.student_roster to authenticated;

drop policy if exists "srmh_student_roster_select_active" on public.student_roster;
create policy "srmh_student_roster_select_active"
    on public.student_roster for select to authenticated
    using ((select public.srmh_is_active_user()));
drop policy if exists "srmh_student_roster_select_restrict" on public.student_roster;
create policy "srmh_student_roster_select_restrict"
    on public.student_roster as restrictive for select to authenticated
    using ((select public.srmh_is_active_user()));

drop policy if exists "srmh_student_roster_insert_admin" on public.student_roster;
create policy "srmh_student_roster_insert_admin"
    on public.student_roster for insert to authenticated
    with check ((select public.srmh_is_active_admin()));
drop policy if exists "srmh_student_roster_insert_restrict" on public.student_roster;
create policy "srmh_student_roster_insert_restrict"
    on public.student_roster as restrictive for insert to authenticated
    with check ((select public.srmh_is_active_admin()));

drop policy if exists "srmh_student_roster_update_active" on public.student_roster;
create policy "srmh_student_roster_update_active"
    on public.student_roster for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));
drop policy if exists "srmh_student_roster_update_restrict" on public.student_roster;
create policy "srmh_student_roster_update_restrict"
    on public.student_roster as restrictive for update to authenticated
    using ((select public.srmh_is_active_user()))
    with check ((select public.srmh_is_active_user()));

-- Bug reports: all active users may read, but only the active reporter may
-- create a report. Resolution is reserved for active Admin accounts.
alter table public.bug_reports enable row level security;
revoke all on public.bug_reports from public, anon, authenticated;
grant select, insert (author_code, author_name, role, content), update (status)
    on public.bug_reports to authenticated;

drop policy if exists "srmh_bug_reports_select_active" on public.bug_reports;
create policy "srmh_bug_reports_select_active"
    on public.bug_reports for select to authenticated
    using ((select public.srmh_is_active_user()));
drop policy if exists "srmh_bug_reports_select_restrict" on public.bug_reports;
create policy "srmh_bug_reports_select_restrict"
    on public.bug_reports as restrictive for select to authenticated
    using ((select public.srmh_is_active_user()));

drop policy if exists "srmh_bug_reports_insert_author" on public.bug_reports;
create policy "srmh_bug_reports_insert_author"
    on public.bug_reports for insert to authenticated
    with check (
        exists (
            select 1
            from public.accounts
            where auth_user_id = (select auth.uid())
              and is_active = true
              and code = author_code
              and name = author_name
              and role = bug_reports.role
        )
    );
drop policy if exists "srmh_bug_reports_insert_restrict" on public.bug_reports;
create policy "srmh_bug_reports_insert_restrict"
    on public.bug_reports as restrictive for insert to authenticated
    with check (
        exists (
            select 1
            from public.accounts
            where auth_user_id = (select auth.uid())
              and is_active = true
              and code = author_code
              and name = author_name
              and role = bug_reports.role
        )
    );

drop policy if exists "srmh_bug_reports_update_admin" on public.bug_reports;
create policy "srmh_bug_reports_update_admin"
    on public.bug_reports for update to authenticated
    using ((select public.srmh_is_active_admin()))
    with check ((select public.srmh_is_active_admin()));
drop policy if exists "srmh_bug_reports_update_restrict" on public.bug_reports;
create policy "srmh_bug_reports_update_restrict"
    on public.bug_reports as restrictive for update to authenticated
    using ((select public.srmh_is_active_admin()))
    with check ((select public.srmh_is_active_admin()));

commit;
