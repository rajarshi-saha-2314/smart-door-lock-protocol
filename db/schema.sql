-- Authentication Server database.
-- Deliberately NOT stored: PW_U, RPW, A, K_DL, x. A and K_DL are recomputed from x on demand.

CREATE TABLE IF NOT EXISTS users (
    ID_U            TEXT PRIMARY KEY,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'faculty', 'cr', 'student')),
    class_id        TEXT,                       -- e.g. CSE-4A (students and CRs)
    card_version    INTEGER NOT NULL DEFAULT 1, -- v in A = h(ID_U ‖ x ‖ v); bumped on card re-issue
    TID_cur         TEXT    NOT NULL UNIQUE,    -- hex, current pseudonym
    TID_old         TEXT    UNIQUE,             -- hex, previous pseudonym (desync protection)
    revoked         INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS doors (
    ID_DL         TEXT PRIMARY KEY,
    port          INTEGER NOT NULL,
    registered_ms INTEGER NOT NULL
);
