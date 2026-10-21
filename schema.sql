CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY,title TEXT NOT NULL,category TEXT NOT NULL,excerpt TEXT NOT NULL,body TEXT NOT NULL,source_url TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),created_at TEXT NOT NULL DEFAULT (datetime('now')),updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status,updated_at);

CREATE TABLE IF NOT EXISTS personal_ads (id TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL,url TEXT NOT NULL,cta TEXT NOT NULL DEFAULT 'Learn more',status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),updated_at TEXT NOT NULL DEFAULT (datetime('now')));
