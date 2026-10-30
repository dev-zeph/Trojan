import { NextResponse } from "next/server";

// Only the admin pages are matched; API routes check the session themselves.
export function middleware() {
  return NextResponse.next();
}

export const config = { matcher: ["/admin/:path*"] };
