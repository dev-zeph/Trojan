import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { getSession } from "@/lib/auth";

// Logged-in users write and read their own notes.
export async function GET() {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const notes = getDb().prepare("SELECT * FROM notes WHERE owner = ?").all(session.id);
  return NextResponse.json({ notes });
}

export async function POST(req: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { body } = await req.json();
  getDb().prepare("INSERT INTO notes (owner, body) VALUES (?, ?)").run(session.id, body);
  return NextResponse.json({ ok: true });
}
