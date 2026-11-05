create table orders (id uuid primary key, user_id uuid, total numeric);
create table profiles (id uuid primary key, email text, full_name text);
create table posts (id uuid primary key, author_id uuid, body text);
create table invoices (id uuid primary key, customer text, amount numeric);
