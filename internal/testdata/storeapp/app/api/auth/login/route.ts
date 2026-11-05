import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

// PLANTED S1: login SQL built by interpolating the request body.
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = getDb()
    .prepare(`SELECT id, role FROM users WHERE email = '${email}' AND password = '${password}'`)
    .get();
  if (!user) return NextResponse.json({ error: "Invalid" }, { status: 401 });
  return NextResponse.json({ ok: true, user });
}
