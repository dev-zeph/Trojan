import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { getSession } from "@/lib/auth";

export async function GET() {
  const session = await getSession();
  if (session?.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  const messages = getDb().prepare("SELECT * FROM messages ORDER BY id DESC").all();
  return NextResponse.json({ messages });
}
