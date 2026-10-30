import { NextResponse } from "next/server";

// Only protects /dashboard. API routes are NOT covered.
export function middleware() {
  return NextResponse.next();
}

export const config = { matcher: ["/dashboard/:path*"] };
