"use client";

import { useEffect, useState } from "react";

type Message = { id: number; name: string; body: string };

const formatText = (s: string) => s.replace(/\n/g, "<br />");

// PLANTED S6: renders contact-form messages (written by a public route) as raw HTML.
export default function AdminPage() {
  const [messages, setMessages] = useState<Message[]>([]);

  async function loadMessages() {
    const res = await fetch("/api/admin/messages");
    if (res.ok) setMessages((await res.json()).messages);
  }

  useEffect(() => {
    loadMessages();
  }, []);

  return (
    <div>
      {messages.map((m) => (
        <div key={m.id}>
          <p>{m.name}</p>
          <div dangerouslySetInnerHTML={{ __html: formatText(m.body) }} />
        </div>
      ))}
    </div>
  );
}
