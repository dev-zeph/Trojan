import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

// SAFE S2: same lookup with a bound parameter.
export async function POST(req: Request) {
  const { email } = await req.json();
  const user = getDb().prepare("SELECT id, role FROM users WHERE email = ?").get(email);
  return NextResponse.json({ user });
}
