import { cookies } from "next/headers";
import jwt from "jsonwebtoken";

export async function getSession() {
  const store = await cookies();
  const token = store.get("session")?.value;
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET ?? "") as { id: number; role: string };
  } catch {
    return null;
  }
}
