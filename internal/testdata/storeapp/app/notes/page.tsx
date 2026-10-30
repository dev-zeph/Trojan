"use client";

import { useEffect, useState } from "react";

// SAFE S7: raw HTML, but notes are only written by logged-in users (their own).
export default function NotesPage() {
  const [notes, setNotes] = useState<{ id: number; body: string }[]>([]);

  useEffect(() => {
    fetch("/api/notes")
      .then((r) => r.json())
      .then((d) => setNotes(d.notes));
  }, []);

  return (
    <ul>
      {notes.map((n) => (
        <li key={n.id} dangerouslySetInnerHTML={{ __html: n.body }} />
      ))}
    </ul>
  );
}
