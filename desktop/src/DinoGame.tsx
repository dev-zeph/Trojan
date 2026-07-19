import { useEffect, useRef, useState } from "react";

const W = 600;
const H = 180;
const GROUND = H - 30;
const GRAVITY = 0.6;
const JUMP_VEL = -13;
const SPEED_INIT = 5;
const SPEED_MAX = 12;
const SPEED_INC = 0.0008;

interface Obstacle {
  x: number;
  w: number;
  h: number;
}

interface GameState {
  running: boolean;
  started: boolean;
  dead: boolean;
  score: number;
  hi: number;
  dinoY: number;
  dinoVY: number;
  onGround: boolean;
  obstacles: Obstacle[];
  speed: number;
  frame: number;
  legPhase: number;
}

function makeObs(_speed: number): Obstacle {
  const h = 24 + Math.random() * 20;
  const w = 10 + Math.random() * 10;
  return { x: W + 40, w, h };
}

function initState(): GameState {
  return {
    running: false,
    started: false,
    dead: false,
    score: 0,
    hi: 0,
    dinoY: GROUND,
    dinoVY: 0,
    onGround: true,
    obstacles: [],
    speed: SPEED_INIT,
    frame: 0,
    legPhase: 0,
  };
}

export function DinoGame() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef<GameState>(initState());
  const rafRef = useRef<number>(0);
  const [displayScore, setDisplayScore] = useState(0);
  const [phase, setPhase] = useState<"idle" | "running" | "dead">("idle");

  function jump() {
    const s = stateRef.current;
    if (s.dead) {
      // restart
      const hi = Math.max(s.hi, s.score);
      stateRef.current = { ...initState(), started: true, running: true, hi };
      setPhase("running");
      setDisplayScore(0);
      return;
    }
    if (!s.started) {
      s.started = true;
      s.running = true;
      setPhase("running");
    }
    if (s.onGround) {
      s.dinoVY = JUMP_VEL;
      s.onGround = false;
    }
  }

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.code === "Space" || e.code === "ArrowUp") {
        e.preventDefault();
        jump();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;

    function drawDino(s: GameState) {
      const x = 60;
      const y = s.dinoY;
      const bodyW = 28;
      const bodyH = 22;

      ctx.fillStyle = "#1a1a1a";

      // Body
      ctx.fillRect(x, y - bodyH, bodyW, bodyH);
      // Head
      ctx.fillRect(x + bodyW - 10, y - bodyH - 14, 20, 14);
      // Eye
      ctx.fillStyle = "#fff";
      ctx.fillRect(x + bodyW + 4, y - bodyH - 11, 4, 4);
      ctx.fillStyle = "#1a1a1a";
      ctx.fillRect(x + bodyW + 5, y - bodyH - 10, 2, 2);
      // Mouth
      ctx.fillStyle = "#1a1a1a";
      ctx.fillRect(x + bodyW + 8, y - bodyH - 5, 4, 2);

      // Legs — alternate phase when running
      ctx.fillStyle = "#1a1a1a";
      if (!s.onGround) {
        // airborne: legs tucked
        ctx.fillRect(x + 4, y - 6, 6, 6);
        ctx.fillRect(x + 14, y - 8, 6, 6);
      } else if (!s.running) {
        // idle: standing
        ctx.fillRect(x + 4, y - 10, 6, 10);
        ctx.fillRect(x + 16, y - 10, 6, 10);
      } else {
        // running animation
        const leg = s.legPhase < 8;
        ctx.fillRect(x + 4, y - (leg ? 12 : 6), 6, leg ? 12 : 6);
        ctx.fillRect(x + 16, y - (leg ? 6 : 12), 6, leg ? 6 : 12);
      }

      // Tail
      ctx.fillStyle = "#1a1a1a";
      ctx.fillRect(x - 8, y - bodyH + 6, 10, 6);
    }

    function tick() {
      const s = stateRef.current;
      ctx.clearRect(0, 0, W, H);

      // Ground
      ctx.fillStyle = "#e5e7eb";
      ctx.fillRect(0, GROUND + 2, W, 2);

      // Clouds (decorative, always scroll slowly)
      ctx.fillStyle = "#f3f4f6";
      const cloudX = (W - (s.frame * 0.4) % W + W) % W;
      ctx.fillRect(cloudX, 20, 50, 10);
      ctx.fillRect(cloudX + 8, 14, 34, 10);
      ctx.fillRect((cloudX + 220) % W, 35, 36, 8);
      ctx.fillRect((cloudX + 228) % W, 30, 20, 8);

      if (!s.started) {
        // Idle state
        drawDino(s);

        ctx.fillStyle = "#6b7280";
        ctx.font = "600 13px Inter, system-ui";
        ctx.textAlign = "center";
        ctx.fillText("Press Space or tap to start", W / 2, GROUND - 40);

        ctx.font = "11px Inter, system-ui";
        ctx.fillStyle = "#9ca3af";
        ctx.fillText("Play while your project scans", W / 2, GROUND - 22);

        rafRef.current = requestAnimationFrame(tick);
        s.frame++;
        return;
      }

      if (s.dead) {
        drawDino(s);

        // Draw obstacles
        ctx.fillStyle = "#374151";
        for (const obs of s.obstacles) {
          ctx.fillRect(obs.x, GROUND - obs.h, obs.w, obs.h);
          // cactus top
          ctx.fillRect(obs.x - 4, GROUND - obs.h - 6, obs.w + 8, 8);
        }

        ctx.fillStyle = "#ef4444";
        ctx.font = "700 14px Inter, system-ui";
        ctx.textAlign = "center";
        ctx.fillText("GAME OVER", W / 2, GROUND - 50);

        ctx.font = "12px Inter, system-ui";
        ctx.fillStyle = "#6b7280";
        ctx.fillText(`Score: ${s.score}   Best: ${s.hi}`, W / 2, GROUND - 30);

        ctx.font = "11px Inter, system-ui";
        ctx.fillText("Press Space or tap to try again", W / 2, GROUND - 12);

        rafRef.current = requestAnimationFrame(tick);
        return;
      }

      // Physics
      s.dinoVY += GRAVITY;
      s.dinoY += s.dinoVY;
      if (s.dinoY >= GROUND) {
        s.dinoY = GROUND;
        s.dinoVY = 0;
        s.onGround = true;
      }

      // Speed ramp
      s.speed = Math.min(SPEED_MAX, SPEED_INIT + s.frame * SPEED_INC);

      // Obstacles
      s.obstacles = s.obstacles.map((o) => ({ ...o, x: o.x - s.speed })).filter((o) => o.x > -60);

      // Spawn new obstacle
      const lastX = s.obstacles.length > 0 ? s.obstacles[s.obstacles.length - 1].x : -Infinity;
      const gap = 200 + Math.random() * 300;
      if (lastX < W - gap) {
        s.obstacles.push(makeObs(s.speed));
      }

      // Collision detection
      const dinoBox = { x: 68, y: s.dinoY - 22, w: 22, h: 22 };
      for (const obs of s.obstacles) {
        if (
          dinoBox.x < obs.x + obs.w &&
          dinoBox.x + dinoBox.w > obs.x &&
          dinoBox.y < GROUND &&
          dinoBox.y + dinoBox.h > GROUND - obs.h
        ) {
          s.dead = true;
          s.hi = Math.max(s.hi, s.score);
          setPhase("dead");
          break;
        }
      }

      // Draw obstacles
      ctx.fillStyle = "#374151";
      for (const obs of s.obstacles) {
        // Cactus body
        ctx.fillRect(obs.x, GROUND - obs.h, obs.w, obs.h);
        // Cactus arms
        ctx.fillRect(obs.x - 5, GROUND - obs.h + 8, 5, 6);
        ctx.fillRect(obs.x + obs.w, GROUND - obs.h + 12, 5, 6);
        ctx.fillRect(obs.x - 5, GROUND - obs.h + 2, 3, 8);
        ctx.fillRect(obs.x + obs.w + 2, GROUND - obs.h + 6, 3, 8);
      }

      drawDino(s);

      // Score
      s.score = Math.floor(s.frame / 6);
      s.legPhase = (s.legPhase + 1) % 16;
      s.frame++;
      setDisplayScore(s.score);

      rafRef.current = requestAnimationFrame(tick);
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  return (
    <div className="dino-wrap" onClick={jump}>
      <canvas
        ref={canvasRef}
        width={W}
        height={H}
        className="dino-canvas"
      />
      {phase === "running" && (
        <div className="dino-score">{String(displayScore).padStart(5, "0")}</div>
      )}
    </div>
  );
}
