/app
  /portal/[token]/page.tsx            # 평가자 포털 페이지(SSR)
  /r/[assignmentToken]/route.ts       # 중계(리다이렉트) API Route (GET)
  /api/admin/upload/route.ts          # CSV 업로드(POST) - 관리자 토큰 보호
  /api/admin/send-links/route.ts      # 포털 링크 일괄 발송(POST)
  /api/webhook/surveymonkey/route.ts  # SurveyMonkey Webhook(POST)
  /layout.tsx
/lib
  supabaseAdmin.ts                    # service_role 키로 서버측 클라이언트
  mailer.ts                           # Resend/SendGrid 메일 유틸
  tokens.ts                           # 토큰 생성 유틸
  csv.ts                              # CSV 파서
