import { useCallback, useEffect, useMemo, useRef, useState } from "react";

/**
 * Steps through a fixed array of DefenderOutput-shaped records over time,
 * simulating a live replay for the demo. Works the same whether `run` came
 * from the mock generator or (later) a real feed already collected into an
 * array.
 */
export function useReplay(run, { intervalMs = 350 } = {}) {
  const [index, setIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const timerRef = useRef(null);

  const total = run.length;
  const clampedIndex = Math.min(index, Math.max(total - 1, 0));

  useEffect(() => {
    if (!isPlaying) return undefined;
    timerRef.current = setInterval(() => {
      setIndex((i) => {
        if (i + 1 >= total) {
          setIsPlaying(false);
          return i;
        }
        return i + 1;
      });
    }, intervalMs / speed);
    return () => clearInterval(timerRef.current);
  }, [isPlaying, speed, intervalMs, total]);

  const play = useCallback(() => {
    if (clampedIndex + 1 >= total) setIndex(0);
    setIsPlaying(true);
  }, [clampedIndex, total]);
  const pause = useCallback(() => setIsPlaying(false), []);
  const reset = useCallback(() => {
    setIsPlaying(false);
    setIndex(0);
  }, []);

  const seek = useCallback(
    (i) => setIndex(Math.min(Math.max(Math.round(i), 0), Math.max(total - 1, 0))),
    [total]
  );

  const history = useMemo(() => run.slice(0, clampedIndex + 1), [run, clampedIndex]);
  const current = history[history.length - 1] ?? null;

  return {
    current,
    history,
    index: clampedIndex,
    total,
    isPlaying,
    speed,
    setSpeed,
    play,
    pause,
    reset,
    seek,
  };
}
