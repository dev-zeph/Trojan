from fastapi import Depends, FastAPI, HTTPException, Request

from db import get_conn, supabase

app = FastAPI()


def get_current_user(request: Request):
    user = request.state.user
    if not user:
        raise HTTPException(status_code=401)
    return user


# PLANTED P1: writes with no auth check.
@app.post("/items")
async def create_item(request: Request):
    body = await request.json()
    return supabase.table("items").insert(body).execute()


# SAFE P2: requires the current user.
@app.get("/me")
async def me(user=Depends(get_current_user)):
    return supabase.table("profiles").select("*").eq("id", user.id).execute()


# PLANTED P3: raw SQL from a query parameter.
@app.get("/search")
async def search(request: Request):
    q = request.query_params.get("q")
    cur = get_conn().cursor()
    cur.execute(f"SELECT * FROM items WHERE name = '{q}'")
    return cur.fetchall()
