import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

// Public contact form: anyone can write to messages (by design).
export async function POST(req: Request) {
  const { name, body } = await req.json();
  getDb().prepare("INSERT INTO messages (name, body) VALUES (?, ?)").run(name, body);
  return NextResponse.json({ ok: true });
}
