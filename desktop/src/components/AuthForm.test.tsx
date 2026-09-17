import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AuthForm } from "./AuthForm";
import { supabase } from "../lib/supabase";
import { openUrl } from "@tauri-apps/plugin-opener";
import { MARKETING_URL } from "../constants";

// Desktop has no real sign-up flow (no email-verification handling, no
// plan/token onboarding, no terms acceptance), so sign-up must hand off to
// the website instead of calling supabase.auth.signUp in-app.
vi.mock("../lib/supabase", () => ({
  supabase: {
    auth: {
      signInWithPassword: vi.fn(),
      signUp: vi.fn(),
    },
  },
}));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(),
}));

describe("AuthForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("opens the website's login page instead of calling supabase.auth.signUp", () => {
    (openUrl as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
    const onAuth = vi.fn();

    render(<AuthForm onAuth={onAuth} />);

    fireEvent.click(screen.getByRole("button", { name: /create one on trojancli\.com/i }));

    expect(openUrl).toHaveBeenCalledWith(`${MARKETING_URL}/login`);
    expect(supabase.auth.signUp).not.toHaveBeenCalled();
  });

  it("still submits credentials via signInWithPassword for the sign-in path", async () => {
    (supabase.auth.signInWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        session: {
          access_token: "tok",
          refresh_token: "refresh",
          user: { user_metadata: { full_name: "Ada" } },
        },
      },
      error: null,
    });
    const onAuth = vi.fn();

    render(<AuthForm onAuth={onAuth} />);

    fireEvent.change(screen.getByPlaceholderText("you@example.com"), { target: { value: "ada@example.com" } });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => expect(onAuth).toHaveBeenCalledWith("tok", "Ada", "ada@example.com", "refresh"));
    expect(supabase.auth.signInWithPassword).toHaveBeenCalledWith({ email: "ada@example.com", password: "hunter2" });
    expect(supabase.auth.signUp).not.toHaveBeenCalled();
  });
});
