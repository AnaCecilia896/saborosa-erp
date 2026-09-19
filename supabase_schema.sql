-- =====================================================================
--  Saborosa Salgados — estrutura do banco de dados
--  Cole este arquivo inteiro no SQL Editor do Supabase e clique em Run.
--  Pode rodar mais de uma vez sem problema: tudo é "if not exists".
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Empresa e membros — o espaço de trabalho compartilhado
-- ---------------------------------------------------------------------

create table if not exists public.empresas (
  id        uuid primary key default gen_random_uuid(),
  nome      text not null,
  criado_em timestamptz not null default now()
);

create table if not exists public.membros (
  empresa_id uuid not null references public.empresas(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  papel      text not null default 'editor',   -- 'dono' | 'editor' | 'leitor'
  criado_em  timestamptz not null default now(),
  primary key (empresa_id, user_id)
);

-- Convite por e-mail: a pessoa vira membro automaticamente ao entrar pela primeira vez.
create table if not exists public.convites (
  empresa_id uuid not null references public.empresas(id) on delete cascade,
  email      text not null,
  papel      text not null default 'editor',
  criado_em  timestamptz not null default now(),
  primary key (empresa_id, email)
);

-- ---------------------------------------------------------------------
-- 2. Os dados do sistema
--
--    Uma linha por registro (um lançamento, um fornecedor, uma conta...).
--    O conteúdo fica em JSONB para o sistema poder ganhar campos novos
--    sem precisar alterar o banco. Como cada registro é uma linha, duas
--    pessoas editando coisas diferentes nunca sobrescrevem uma à outra.
-- ---------------------------------------------------------------------

create table if not exists public.registros (
  empresa_id     uuid not null references public.empresas(id) on delete cascade,
  tipo           text not null,   -- plano | conta | fornecedor | funcionario | lancamento | transacao | meta
  id             text not null,
  dados          jsonb not null,
  atualizado_em  timestamptz not null default now(),
  atualizado_por uuid references auth.users(id),
  primary key (empresa_id, tipo, id)
);

create index if not exists registros_empresa_tipo_idx on public.registros (empresa_id, tipo);

-- Consultas diretas no SQL continuam possíveis, por exemplo:
--   select dados->>'parceiro', (dados->>'valor')::numeric
--   from registros where tipo = 'lancamento' and dados->>'competencia' = '2026-09';

-- ---------------------------------------------------------------------
-- 3. Funções auxiliares
-- ---------------------------------------------------------------------

-- Empresas às quais o usuário logado pertence.
create or replace function public.minhas_empresas()
returns setof uuid
language sql
security definer
set search_path = public
stable
as $$
  select empresa_id from public.membros where user_id = auth.uid();
$$;

-- Cria a empresa e já põe quem criou como dono.
create or replace function public.criar_empresa(p_nome text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  if auth.uid() is null then
    raise exception 'É preciso estar autenticado.';
  end if;

  insert into public.empresas (nome) values (p_nome) returning id into v_id;
  insert into public.membros (empresa_id, user_id, papel) values (v_id, auth.uid(), 'dono');
  return v_id;
end;
$$;

-- Converte convites pendentes em acesso efetivo. Chamada logo após o login.
create or replace function public.aceitar_convites()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text;
  v_qtd   integer;
begin
  select email into v_email from auth.users where id = auth.uid();
  if v_email is null then
    return 0;
  end if;

  insert into public.membros (empresa_id, user_id, papel)
  select c.empresa_id, auth.uid(), c.papel
  from public.convites c
  where lower(c.email) = lower(v_email)
  on conflict (empresa_id, user_id) do nothing;

  get diagnostics v_qtd = row_count;

  delete from public.convites c where lower(c.email) = lower(v_email);
  return v_qtd;
end;
$$;

-- Lista quem tem acesso (para a tela de Config mostrar).
create or replace function public.listar_acessos(p_empresa uuid)
returns table (email text, papel text, situacao text)
language sql
security definer
set search_path = public
stable
as $$
  select u.email::text, m.papel, 'ativo'::text
  from public.membros m
  join auth.users u on u.id = m.user_id
  where m.empresa_id = p_empresa
    and p_empresa in (select public.minhas_empresas())
  union all
  select c.email, c.papel, 'convite pendente'
  from public.convites c
  where c.empresa_id = p_empresa
    and p_empresa in (select public.minhas_empresas());
$$;

-- ---------------------------------------------------------------------
-- 4. Segurança: ninguém vê dados de empresa que não seja sua
-- ---------------------------------------------------------------------

alter table public.empresas  enable row level security;
alter table public.membros   enable row level security;
alter table public.convites  enable row level security;
alter table public.registros enable row level security;

drop policy if exists empresas_ler     on public.empresas;
drop policy if exists membros_ler      on public.membros;
drop policy if exists convites_ler     on public.convites;
drop policy if exists convites_criar   on public.convites;
drop policy if exists convites_apagar  on public.convites;
drop policy if exists registros_ler    on public.registros;
drop policy if exists registros_gravar on public.registros;
drop policy if exists registros_editar on public.registros;
drop policy if exists registros_apagar on public.registros;

create policy empresas_ler on public.empresas
  for select using (id in (select public.minhas_empresas()));

create policy membros_ler on public.membros
  for select using (empresa_id in (select public.minhas_empresas()));

-- Só o dono mexe em convites.
create policy convites_ler on public.convites
  for select using (empresa_id in (select public.minhas_empresas()));

create policy convites_criar on public.convites
  for insert with check (
    exists (select 1 from public.membros m
            where m.empresa_id = convites.empresa_id
              and m.user_id = auth.uid() and m.papel = 'dono')
  );

create policy convites_apagar on public.convites
  for delete using (
    exists (select 1 from public.membros m
            where m.empresa_id = convites.empresa_id
              and m.user_id = auth.uid() and m.papel = 'dono')
  );

-- Dados: leitura para qualquer membro; escrita para quem não é apenas leitor.
create policy registros_ler on public.registros
  for select using (empresa_id in (select public.minhas_empresas()));

create policy registros_gravar on public.registros
  for insert with check (
    exists (select 1 from public.membros m
            where m.empresa_id = registros.empresa_id
              and m.user_id = auth.uid() and m.papel in ('dono', 'editor'))
  );

create policy registros_editar on public.registros
  for update using (
    exists (select 1 from public.membros m
            where m.empresa_id = registros.empresa_id
              and m.user_id = auth.uid() and m.papel in ('dono', 'editor'))
  );

create policy registros_apagar on public.registros
  for delete using (
    exists (select 1 from public.membros m
            where m.empresa_id = registros.empresa_id
              and m.user_id = auth.uid() and m.papel in ('dono', 'editor'))
  );

-- ---------------------------------------------------------------------
-- 5. Avisar o outro navegador quando alguém gravar algo
-- ---------------------------------------------------------------------

alter publication supabase_realtime add table public.registros;
