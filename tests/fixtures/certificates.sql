PRAGMA foreign_keys = ON;
CREATE TABLE hosting_acme_issuers (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, cn TEXT NOT NULL UNIQUE);
CREATE TABLE hosting_acme_accounts (id INTEGER PRIMARY KEY, issuer_id INTEGER NOT NULL REFERENCES hosting_acme_issuers(id));
CREATE TABLE hosting_servers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z', enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE hosting_certificate_issuers (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL CHECK(kind IN ('acme','local_ca')),
 acme_account_id INTEGER UNIQUE REFERENCES hosting_acme_accounts(id),
 ca_certificate_id INTEGER UNIQUE REFERENCES hosting_certificates(id),
 CHECK ((kind='acme' AND acme_account_id IS NOT NULL AND ca_certificate_id IS NULL) OR
        (kind='local_ca' AND ca_certificate_id IS NOT NULL AND acme_account_id IS NULL))
);
CREATE TABLE hosting_certificates (
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('server','client','ca')),
 issuer_id INTEGER REFERENCES hosting_certificate_issuers(id), cn TEXT NOT NULL UNIQUE,
 certs_der BLOB NOT NULL, key_der BLOB NOT NULL, expires_at TEXT NOT NULL, issued_at TEXT NOT NULL,
 updated_at TEXT, revoked_at TEXT, enabled INTEGER NOT NULL, CHECK (issuer_id IS NOT NULL OR kind='ca')
);
CREATE TABLE hosting_cert_aliases (
 id INTEGER PRIMARY KEY, cert_id INTEGER NOT NULL REFERENCES hosting_certificates(id) ON DELETE CASCADE,
 hostname TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(cert_id, hostname)
);
CREATE TABLE hosting_certificate_server (
 certificate_id INTEGER NOT NULL REFERENCES hosting_certificates(id) ON DELETE CASCADE,
 server_id INTEGER NOT NULL REFERENCES hosting_servers(id), created_at TEXT NOT NULL,
 PRIMARY KEY(certificate_id,server_id)
);
INSERT INTO hosting_acme_issuers VALUES (1,'Fixture CA','public-ca.test');
INSERT INTO hosting_acme_accounts VALUES (1,1);
INSERT INTO hosting_servers (id,name) VALUES (1,'edge.test');
