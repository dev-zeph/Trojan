from flask import Flask
from flask_login import login_required

from db import supabase

app = Flask(__name__)


# PLANTED P4: admin delete with no login check.
@app.route("/admin/delete/<item_id>", methods=["POST"])
def admin_delete(item_id):
    supabase.table("items").delete().eq("id", item_id).execute()
    return "deleted"


# SAFE P5: protected by login_required.
@app.route("/account", methods=["GET"])
@login_required
def account():
    return supabase.table("profiles").select("*").execute().data
