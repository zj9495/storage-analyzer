ALTER TABLE admin_users
    ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
