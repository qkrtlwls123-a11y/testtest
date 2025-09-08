# Build a Next.js (Vercel) + Supabase starter with admin UI & all server routes, plus SQL schema.
import os, zipfile, pathlib, textwrap, json

BASE = "/mnt/data/vercel_supabase_portal"
def ensure(p): os.makedirs(os.path.join(BASE, p), exist_ok=True)
def w(path, content):
    p = os.path.join(BASE, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content).lstrip())

# Root files
w("package.json", """
{
  "name": "surveymonkey-360-portal",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "echo 'skip'"
  },
  "dependencies": {
    "@supabase/supabase-js": "2.45.4",
    "next": "14.2.5",
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "resend": "3.4.0"
  },
  "type": "module"
}
""")

w("tsconfig.json", """
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "es2022"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "baseUrl": ".",
    "types": ["node"]
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
""")

w("next.config.mjs", """
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {},
};
export default nextConfig;
""")

w(".env.example", """
NEXT_PUBLIC_BASE_URL=http://localhost:3000

SUPABASE_URL=<<your-supabase-url>>
SUPABASE_SERVICE_ROLE_KEY=<<your-supabase-service-role-key>>

ADMIN_API_TOKEN=change_me_strong

SM_BASE_SURVEY_URL=https://www.surveymonkey.com/r/XXXX
SM_WEBHOOK_SECRET=change_me

RESEND_API_KEY=<<your-resend-api-key>>
FROM_EMAIL=no-reply@example.com
""")

# SQL schema
w("supabase_schema.sql", """
-- Supabase schema for SurveyMonkey 360 portal
create schema if not exists app;

create table if not exists app.evaluators (
  id bigserial primary key,
  email text not null unique,
  name text not null,
  evaluator_code text not null,
  portal_token text not null unique,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists app.leaders (
  id bigserial primary key,
  name text not null,
  leader_code text not null unique,
  created_at timestamptz not null default now()
);

do $$ begin
  create type app.assignment_status as enum ('ASSIGNED','COMPLETED');
exception
  when duplicate_object then null;
end $$;

create table if not exists app.assignments (
  id bigserial primary key,
  evaluator_id bigint not null references app.evaluators(id) on delete cascade,
  leader_id bigint not null references app.leaders(id) on delete cascade,
  assignment_token text not null unique,
  survey_url text not null,
  status app.assignment_status not null default 'ASSIGNED',
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  unique (evaluator_id, leader_id)
);

create index if not exists idx_assignments_eval on app.assignments(evaluator_id);
create index if not exists idx_assignments_token on app.assignments(assignment_token);

alter table app.evaluators enable row level security;
alter table app.leaders enable row level security;
alter table app.assignments enable row level security;
-- NOTE: We will use service_role key from server. No public policies created.
""")

# lib files
w("lib/supabaseAdmin.ts", """
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } }
);
""")

w("lib/tokens.ts", """
import crypto from 'crypto';
export const genToken = (len = 32) => crypto.randomBytes(len).toString('base64url');
""")

w("lib/mailer.ts", """
import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendMail(to: string, subject: string, html: string) {
  if (!process.env.RESEND_API_KEY) throw new Error('RESEND_API_KEY missing');
  await resend.emails.send({
    from: process.env.FROM_EMAIL!,
    to,
    subject,
    html,
  });
}
""")

w("lib/csv.ts", """
export async function parseCsv(file: File): Promise<Array<Record<string,string>>> {
  const text = await file.text();
  const lines = text.split(/\\r?\\n/).filter(l => l.trim().length);
  if (!lines.length) return [];
  const headers = lines[0].split(',').map(h => h.trim());
  const rows = [];
  for (let i=1;i<lines.length;i++) {
    const cols = lines[i].split(',').map(c => c.trim());
    const row: Record<string,string> = {};
    headers.forEach((h, idx) => row[h] = cols[idx] ?? '');
    rows.push(row);
  }
  return rows;
}
""")

# app layout/home
w("app/layout.tsx", """
export const metadata = { title: '360 Portal' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body style={{fontFamily:'system-ui', margin:0, padding:20}}>{children}</body>
    </html>
  );
}
""")

w("app/page.tsx", """
export default function Home() {
  return (
    <main>
      <h2>OK: SurveyMonkey 360 Portal (Vercel + Supabase)</h2>
      <p>관리자 페이지: <a href="/admin" target="_self">/admin</a></p>
    </main>
  );
}
""")

# Admin page (client)
w("app/admin/page.tsx", """
'use client';

import { useState } from 'react';

export default function AdminPage() {
  const [token, setToken] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [msg, setMsg] = useState('');
  const [sending, setSending] = useState(false);

  const sample = `evaluator_email,evaluator_name,evaluator_code,leader_name,leader_code
kim@company.com,김철수,E01,리더A,L05
kim@company.com,김철수,E01,리더B,L07
lee@company.com,이영희,E02,리더C,L03`;

  const upload = async () => {
    if (!file) { setMsg('CSV 파일을 선택해 주세요.'); return; }
    if (!token) { setMsg('관리자 토큰을 입력해 주세요.'); return; }
    setSending(true);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/admin/upload', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${token}` },
        body: fd
      });
      const data = await res.json();
      setMsg(res.ok ? '업로드 성공' : `오류: ${data?.error || res.statusText}`);
    } catch (e: any) {
      setMsg('업로드 중 오류: ' + e.message);
    } finally { setSending(false); }
  };

  const sendLinks = async () => {
    if (!token) { setMsg('관리자 토큰을 입력해 주세요.'); return; }
    setSending(true);
    try {
      const res = await fetch('/api/admin/send-links', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setMsg(res.ok ? `메일 발송: ${data.sent}건` : `오류: ${data?.error || res.statusText}`);
    } catch (e: any) {
      setMsg('발송 중 오류: ' + e.message);
    } finally { setSending(false); }
  };

  return (
    <main style={{maxWidth:720, margin:'0 auto'}}>
      <h2>관리자 페이지</h2>

      <section style={{padding:'12px 0'}}>
        <label>관리자 API 토큰: </label>
        <input value={token} onChange={e=>setToken(e.target.value)} style={{width:'60%'}} placeholder="Vercel 환경변수 ADMIN_API_TOKEN 값" />
      </section>

      <section style={{padding:'12px 0'}}>
        <h3>1) CSV 업로드</h3>
        <input type="file" accept=".csv" onChange={e=>setFile(e.target.files?.[0] || null)} />
        <button onClick={upload} disabled={sending} style={{marginLeft:10}}>업로드</button>
        <details style={{marginTop:10}}>
          <summary>CSV 예시 보기</summary>
          <pre>{sample}</pre>
        </details>
      </section>

      <section style={{padding:'12px 0'}}>
        <h3>2) 포털 링크 일괄 발송</h3>
        <button onClick={sendLinks} disabled={sending}>메일 발송</button>
        <p style={{fontSize:12, color:'#666'}}>※ RESEND_API_KEY / FROM_EMAIL 환경변수 필요. 미설정 시 실패합니다.</p>
      </section>

      {msg && <p style={{marginTop:20}}><strong>{msg}</strong></p>}
    </main>
  );
}
""")

# Portal page
w("app/portal/[token]/page.tsx", """
import { supabaseAdmin } from '@/lib/supabaseAdmin';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

async function getData(token: string) {
  const { data: ev, error: e1 } = await supabaseAdmin
    .from('app.evaluators')
    .select('id, name, is_active')
    .eq('portal_token', token)
    .maybeSingle();

  if (!ev || !ev.is_active) return null;

  const { data: list, error: e2 } = await supabaseAdmin
    .from('app.assignments')
    .select('assignment_token,status,leaders:leader_id(name)')
    .eq('evaluator_id', ev.id);

  return { ev, list: list ?? [] };
}

export default async function Page({ params }: { params: { token: string } }) {
  const data = await getData(params.token);
  if (!data) return <div>잘못된 링크이거나 비활성화된 계정입니다.</div>;

  const { ev, list } = data;
  return (
    <main style={{maxWidth:720, margin:'40px auto', fontFamily:'system-ui'}}>
      <h2>{ev.name}님의 진단 대상자</h2>
      <ul>
        {list.map((a: any) => (
          <li key={a.assignment_token} style={{margin:'10px 0'}}>
            {a.leaders?.name ?? '리더'} —{' '}
            {a.status === 'COMPLETED' ? (
              <strong>완료됨</strong>
            ) : (
              <Link href={`/r/${a.assignment_token}`} target="_blank">진단하기</Link>
            )}
          </li>
        ))}
      </ul>
      <p>※ 제출 후 재진입이 차단됩니다.</p>
    </main>
  );
}
""")

# Redirect route
w("app/r/[assignmentToken]/route.ts", """
import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabaseAdmin';

export const runtime = 'nodejs';

export async function GET(
  req: NextRequest,
  { params }: { params: { assignmentToken: string } }
) {
  const token = params.assignmentToken;
  const { data: asn } = await supabaseAdmin
    .from('app.assignments')
    .select('status,survey_url')
    .eq('assignment_token', token)
    .maybeSingle();

  if (!asn) {
    return new NextResponse('유효하지 않은 링크입니다.', { status: 404 });
  }
  if (asn.status === 'COMPLETED') {
    return new NextResponse('이미 완료된 진단입니다. 재응답이 불가합니다.');
  }
  return NextResponse.redirect(asn.survey_url, { status: 302 });
}
""")

# Webhook route
w("app/api/webhook/surveymonkey/route.ts", """
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { supabaseAdmin } from '@/lib/supabaseAdmin';

export const runtime = 'nodejs';

function verify(body: string, signature: string | null) {
  const secret = process.env.SM_WEBHOOK_SECRET;
  if (!secret) return true;
  if (!signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

export async function POST(req: NextRequest) {
  const bodyText = await req.text();
  const signature = req.headers.get('x-sm-signature');
  if (!verify(bodyText, signature)) {
    return NextResponse.json({ error: 'invalid signature' }, { status: 401 });
  }
  const payload = JSON.parse(bodyText || '{}');
  const assign = payload?.custom_variables?.assign;
  if (!assign) return NextResponse.json({ ok: true });
  await supabaseAdmin
    .from('app.assignments')
    .update({ status: 'COMPLETED', completed_at: new Date().toISOString() })
    .eq('assignment_token', assign);
  return NextResponse.json({ ok: true });
}
""")

# Admin upload route
w("app/api/admin/upload/route.ts", """
import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabaseAdmin';
import { genToken } from '@/lib/tokens';

export const runtime = 'nodejs';

async function parseCsv(file: File): Promise<Array<Record<string,string>>> {
  const text = await file.text();
  const lines = text.split(/\\r?\\n/).filter(l => l.trim().length);
  if (!lines.length) return [];
  const headers = lines[0].split(',').map(h => h.trim());
  const rows = [];
  for (let i=1;i<lines.length;i++) {
    const cols = lines[i].split(',').map(c => c.trim());
    const row: Record<string,string> = {};
    headers.forEach((h, idx) => row[h] = cols[idx] ?? '');
    rows.push(row);
  }
  return rows;
}

export async function POST(req: NextRequest) {
  const auth = req.headers.get('authorization');
  if (auth !== `Bearer ${process.env.ADMIN_API_TOKEN}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const form = await req.formData();
  const file = form.get('file') as File | null;
  if (!file) return NextResponse.json({ error: 'file missing' }, { status: 400 });

  const rows = await parseCsv(file);
  for (const row of rows) {
    const { evaluator_email, evaluator_name, evaluator_code, leader_name, leader_code } = row;

    // evaluator upsert
    let { data: evd } = await supabaseAdmin
      .from('app.evaluators')
      .select('id, portal_token')
      .eq('email', evaluator_email)
      .maybeSingle();

    if (!evd) {
      const portal_token = genToken(24);
      const { data: ins } = await supabaseAdmin
        .from('app.evaluators')
        .insert({
          email: evaluator_email,
          name: evaluator_name,
          evaluator_code,
          portal_token,
          is_active: true,
        })
        .select('id, portal_token')
        .single();
      evd = ins!;
    }

    // leader upsert
    let { data: ldd } = await supabaseAdmin
      .from('app.leaders')
      .select('id')
      .eq('leader_code', leader_code)
      .maybeSingle();

    if (!ldd) {
      const { data: ins } = await supabaseAdmin
        .from('app.leaders')
        .insert({ name: leader_name, leader_code })
        .select('id')
        .single();
      ldd = ins!;
    }

    // assignment upsert
    const { data: already } = await supabaseAdmin
      .from('app.assignments')
      .select('id')
      .eq('evaluator_id', evd.id)
      .eq('leader_id', ldd.id)
      .maybeSingle();

    if (!already) {
      const assignment_token = genToken(24);
      const sm = new URL(process.env.SM_BASE_SURVEY_URL!);
      sm.searchParams.set('evaluator', evaluator_code);
      sm.searchParams.set('leader', leader_code);
      sm.searchParams.set('assign', assignment_token);

      await supabaseAdmin.from('app.assignments').insert({
        evaluator_id: evd.id,
        leader_id: ldd.id,
        assignment_token,
        survey_url: sm.toString(),
        status: 'ASSIGNED',
      });
    }
  }

  return NextResponse.json({ ok: true });
}
""")

# Admin send links route
w("app/api/admin/send-links/route.ts", """
import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabaseAdmin';
import { sendMail } from '@/lib/mailer';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const auth = req.headers.get('authorization');
  if (auth !== `Bearer ${process.env.ADMIN_API_TOKEN}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { data: evaluators } = await supabaseAdmin
    .from('app.evaluators')
    .select('name,email,portal_token')
    .eq('is_active', true);

  const base = process.env.NEXT_PUBLIC_BASE_URL!;
  let sent = 0;
  for (const ev of evaluators ?? []) {
    const url = `${base}/portal/${ev.portal_token}`;
    const html = `
      <p>${ev.name}님, 안녕하세요.</p>
      <p>아래 링크에서 배정된 리더에 대한 진단을 진행해 주세요.</p>
      <p><a href="${url}">${url}</a></p>
      <p>각 링크는 1회만 응답 가능하며, 완료 후 재진입이 차단됩니다.</p>
    `;
    await sendMail(ev.email, '리더십 다면진단 포털 링크', html);
    sent++;
  }
  return NextResponse.json({ sent });
}
""")

# Home next-env
w("next-env.d.ts", "/// <reference types=\"next\" />\n/// <reference types=\"next/image-types/global\" />\n")

# README
w("README.md", """
# Vercel + Supabase: SurveyMonkey 360° 포털

## 개요
- 평가자 포털: `/portal/[portalToken]`
- 중계(재진입 차단): `/r/[assignmentToken]`
- 관리자: `/admin` (CSV 업로드·발송 JS UI, ADMIN_API_TOKEN 필요)
- Webhook: `POST /api/webhook/surveymonkey`

## 빠른 시작
1) Supabase에서 `supabase_schema.sql` 실행
2) Vercel에 본 프로젝트 업로드 후 환경변수 설정
3) 배포 URL을 `NEXT_PUBLIC_BASE_URL`로 설정
4) `/admin`에서 CSV 업로드 및 발송 실행
""")

# Zip
zip_path = "/mnt/data/vercel_supabase_portal.zip"
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(BASE):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, BASE)
            z.write(full, arc)

zip_path
