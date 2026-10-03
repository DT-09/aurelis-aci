# Control Engine

The control engine follows `DISCOVER → CONTEXT → POLICY → RISK → DECISION → ACTION → EVIDENCE`. Decisions are ALLOW, ALLOW_WITH_CONSTRAINTS, DENY, ESCALATE or REQUIRE_APPROVAL. The current reference implementation is deterministic and explainable; policy and risk rules are intentionally inspectable.
