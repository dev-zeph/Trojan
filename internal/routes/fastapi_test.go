package routes

import (
	"sort"
	"strings"
	"testing"
)

func TestExtractFastAPI(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "requirements.txt", "fastapi\nuvicorn")
	mkfile(t, dir, "main.py", `
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter(prefix="/users")

@app.get("/health")
async def health():
    return {"ok": True}

@router.get("/{id}")
async def get_user(id: str):
    return id

@router.post("/")
def create_user():
    pass

@app.get("/files/{path:path}")
def serve(path: str):
    pass

app.include_router(router, prefix="/api")
`)

	got := extractFastAPI(dir)
	byPath := map[string]Route{}
	var keys []string
	for _, r := range got {
		byPath[r.Method+" "+r.PathPattern] = r
		keys = append(keys, r.Method+" "+r.PathPattern)
	}
	sort.Strings(keys)
	want := []string{
		"GET /api/users/{id}",     // APIRouter(prefix=/users) + include_router(prefix=/api)
		"GET /files/{path...}",    // {path:path} catch-all
		"GET /health",
		"POST /api/users",         // router POST "/" with combined prefix
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("fastapi routes:\n got: %v\nwant: %v", keys, want)
	}
	// Handler symbol from the def below the decorator.
	if got := byPath["GET /api/users/{id}"]; got.HandlerSymbol != "get_user" {
		t.Errorf("handler symbol = %q, want get_user", got.HandlerSymbol)
	}
}
