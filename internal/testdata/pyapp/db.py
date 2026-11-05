import os

import psycopg2
from supabase import create_client

supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])


def get_conn():
    return psycopg2.connect(os.environ["DATABASE_URL"])
