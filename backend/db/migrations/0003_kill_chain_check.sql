-- The one enum column 0001 left unconstrained.
--
-- alerts.kill_chain_stage is TEXT NOT NULL with no CHECK, while the other five
-- enum columns (severity, threat_class, score_type, event_scope, and incidents
-- .severity) all have one. The inconsistency is not harmful today - the value
-- is derived by the backend from a frozen mapping, not supplied by a detector -
-- but the column is indexed on and read by the incident ribbon, and a typo in a
-- future projection change would land silently.
--
-- The vocabulary is app/schemas/enums.py::KillChainStage.

ALTER TABLE alerts
    ADD CONSTRAINT alerts_kill_chain_stage_enum
    CHECK (kill_chain_stage IN ('recon', 'c2', 'exfil', 'impact'));
