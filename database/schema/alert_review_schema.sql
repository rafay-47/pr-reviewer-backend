-- Schema for AI Code-Scanning Alert Review Service
-- Retains static alert triage runs, adversarial verification, and human outcomes for calibration

CREATE TABLE IF NOT EXISTS public.alert_reviews (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  alert_id text NOT NULL,
  repo text NOT NULL,
  commit_sha text NOT NULL,
  rule_id text NOT NULL,
  determination text NOT NULL CHECK (determination = ANY (ARRAY['TRUE_POSITIVE'::text, 'FALSE_POSITIVE'::text, 'NEEDS_REVIEW'::text, 'ACCEPTABLE_RISK'::text, 'INSUFFICIENT_EVIDENCE'::text])),
  confidence_score double precision NOT NULL,
  confidence_level text NOT NULL CHECK (confidence_level = ANY (ARRAY['HIGH'::text, 'MEDIUM'::text, 'LOW'::text])),
  recommendation text DEFAULT 'manual_review'::text,
  appsec_decision text DEFAULT 'PENDING'::text,
  is_stale boolean DEFAULT false,
  pr_comment_id bigint,
  developer_feedback text,
  developer_questions jsonb DEFAULT '[]'::jsonb,
  missing_evidence jsonb DEFAULT '[]'::jsonb,
  executive_summary text,
  markdown_report text,
  agent_version text DEFAULT '1.0.0-alert-review'::text,
  raw_report jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT alert_reviews_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_alert_reviews_alert_id ON public.alert_reviews(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_reviews_repo ON public.alert_reviews(repo);
CREATE INDEX IF NOT EXISTS idx_alert_reviews_rule_id ON public.alert_reviews(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_reviews_determination ON public.alert_reviews(determination);

CREATE TABLE IF NOT EXISTS public.alert_human_outcomes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  alert_id text NOT NULL,
  repo text NOT NULL,
  human_verdict text NOT NULL CHECK (human_verdict = ANY (ARRAY['TRUE_POSITIVE'::text, 'FALSE_POSITIVE'::text, 'ACCEPTABLE_RISK'::text])),
  human_notes text,
  reviewer_id text,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT alert_human_outcomes_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_alert_human_outcomes_alert_id ON public.alert_human_outcomes(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_human_outcomes_repo ON public.alert_human_outcomes(repo);
