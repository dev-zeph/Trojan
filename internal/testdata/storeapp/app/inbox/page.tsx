"use client";

import { useEffect, useState } from "react";
import DOMPurify from "isomorphic-dompurify";

// SAFE S8: the same public messages, sanitized before rendering.
export default function InboxPage() {
  const [messages, setMessages] = useState<{ id: number; body: string }[]>([]);

  useEffect(() => {
    fetch("/api/admin/messages")
      .then((r) => r.json())
      .then((d) => setMessages(d.messages));
  }, []);

  return (
    <div>
      {messages.map((m) => (
        <div key={m.id} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(m.body) }} />
      ))}
    </div>
  );
}
