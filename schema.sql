-- ============================================================
-- S3M NAC System — PostgreSQL Schema
-- ============================================================
-- FreeRADIUS uyumlu tablolar + FastAPI policy engine tabloları.
-- Tüm şifreler bcrypt ile hashlenir (plaintext kabul edilmez).
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ──────────────────────────────────────────────
-- radcheck: Kullanıcı Kimlik Bilgileri (PAP/CHAP)
-- FreeRADIUS sql modülü bu tabloyu okur.
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radcheck (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        VARCHAR(2)   NOT NULL DEFAULT '==',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);

-- ──────────────────────────────────────────────
-- radreply: Kullanıcıya Özel Dönülecek Atribütler
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radreply (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        VARCHAR(2)   NOT NULL DEFAULT '=',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);

-- ──────────────────────────────────────────────
-- radusergroup: Kullanıcı ↔ Grup İlişkileri
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radusergroup (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority  INTEGER     NOT NULL DEFAULT 1
);

-- ──────────────────────────────────────────────
-- radgroupreply: Grup Bazlı Atribütler (VLAN vb.)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radgroupreply (
    id        SERIAL PRIMARY KEY,
    groupname VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        VARCHAR(2)   NOT NULL DEFAULT '=',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);

-- ──────────────────────────────────────────────
-- radacct: RADIUS Accounting Kayıtları
-- username, NAS IP, oturum süresi, aktarılan veri,
-- başlangıç/bitiş zamanı burada saklanır.
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS radacct (
    radacctid         BIGSERIAL PRIMARY KEY,
    acctsessionid     VARCHAR(64)  NOT NULL DEFAULT '',
    acctuniqueid      VARCHAR(32)  NOT NULL DEFAULT '',
    username          VARCHAR(64)  NOT NULL DEFAULT '',
    realm             VARCHAR(64)  DEFAULT '',
    nasipaddress      INET         NOT NULL,
    nasportid         VARCHAR(32)  DEFAULT NULL,
    nasporttype       VARCHAR(32)  DEFAULT NULL,
    acctstarttime     TIMESTAMP WITH TIME ZONE NULL,
    acctupdatetime    TIMESTAMP WITH TIME ZONE NULL,
    acctstoptime      TIMESTAMP WITH TIME ZONE NULL,
    acctsessiontime   BIGINT       NULL,
    acctauthentic     VARCHAR(32)  DEFAULT NULL,
    connectinfo_start VARCHAR(128) DEFAULT NULL,
    connectinfo_stop  VARCHAR(128) DEFAULT NULL,
    acctinputoctets   BIGINT       NULL,
    acctoutputoctets  BIGINT       NULL,
    calledstationid   VARCHAR(50)  NOT NULL DEFAULT '',
    callingstationid  VARCHAR(50)  NOT NULL DEFAULT '',
    acctterminatecause VARCHAR(32) NOT NULL DEFAULT '',
    servicetype       VARCHAR(32)  DEFAULT NULL,
    framedprotocol    VARCHAR(32)  DEFAULT NULL,
    framedipaddress   INET         NULL
);

-- ──────────────────────────────────────────────
-- users: FastAPI Policy Engine Kullanıcı Tablosu
-- Şifreler bcrypt hash olarak saklanır.
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  UNIQUE NOT NULL,
    password    VARCHAR(255) NOT NULL,   -- bcrypt hash
    mac_address VARCHAR(32)  DEFAULT NULL,
    is_active   BOOLEAN      DEFAULT TRUE,
    role        VARCHAR(16)  NOT NULL DEFAULT 'guest'
);

-- Uyumluluk — önceki sprintten gelen şema farklılıkları
ALTER TABLE users ADD COLUMN IF NOT EXISTS mac_address VARCHAR(32) DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'guest';


-- ============================================================
-- SEED DATA
-- ============================================================

-- ▸ VLAN Politikaları (admin=10, employee=20, guest=30)
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('admin',    'Tunnel-Type',             '=', 'VLAN'),
    ('admin',    'Tunnel-Medium-Type',      '=', 'IEEE-802'),
    ('admin',    'Tunnel-Private-Group-Id', '=', '10'),

    ('employee', 'Tunnel-Type',             '=', 'VLAN'),
    ('employee', 'Tunnel-Medium-Type',      '=', 'IEEE-802'),
    ('employee', 'Tunnel-Private-Group-Id', '=', '20'),

    ('guest',    'Tunnel-Type',             '=', 'VLAN'),
    ('guest',    'Tunnel-Medium-Type',      '=', 'IEEE-802'),
    ('guest',    'Tunnel-Private-Group-Id', '=', '30')
;

-- ▸ Kullanıcı → Grup eşlemeleri
INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('testuser',  'admin',    1),
    ('employee1', 'employee', 1),
    ('guest1',    'guest',    1)
;

-- ▸ Demo Kullanıcılar (şifreler bcrypt ile hashlenir)
INSERT INTO users (username, password, mac_address, is_active, role) VALUES
    ('testuser',  crypt('testing123',  gen_salt('bf')), 'AA:BB:CC:DD:EE:FF', TRUE, 'admin'),
    ('employee1', crypt('employee123', gen_salt('bf')), '11:22:33:44:55:66', TRUE, 'employee'),
    ('guest1',    crypt('guest123',    gen_salt('bf')), '22:33:44:55:66:77', TRUE, 'guest')
ON CONFLICT (username) DO UPDATE SET
    password    = EXCLUDED.password,
    mac_address = EXCLUDED.mac_address,
    is_active   = EXCLUDED.is_active,
    role        = EXCLUDED.role;

-- ▸ radcheck — FreeRADIUS sql modülü için (Cleartext-Password gerekli)
--   NOT: rlm_rest kullandığımız için bu tablo doğrudan kullanılmaz,
--   ancak FreeRADIUS sql modülü fallback olarak bu tabloyu okur.
INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('testuser',  'Cleartext-Password', ':=', 'testing123'),
    ('employee1', 'Cleartext-Password', ':=', 'employee123'),
    ('guest1',    'Cleartext-Password', ':=', 'guest123')
ON CONFLICT DO NOTHING;
