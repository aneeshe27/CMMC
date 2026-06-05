#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, os, json, gzip, statistics
from collections import defaultdict, Counter

import matplotlib.pyplot as plt


def read_jsonl(path):
    """Stream JSONL (supports .gz). Yields dicts; skips bad lines."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                # skip malformed
                continue


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    return p


def rolling_mean(xs, win):
    """causal / expanding moving avg up to window size"""
    if win <= 1:
        return xs
    out = []
    s = 0.0
    q = []
    for v in xs:
        q.append(v)
        s += v
        if len(q) > win:
            s -= q.pop(0)
        out.append(s / len(q))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="smol2.0_grpo3_wlogs/completions.jsonl",
                    help="Path to completions.jsonl (train-time logs)")
    ap.add_argument("--outdir", default="smol2.0_grpo3_wlogs/analysis",
                    help="Where to write CSVs and PNGs")
    ap.add_argument("--roll", type=int, default=50,
                    help="Rolling window (steps) for smoothed curves AND rolling perfect counts")
    ap.add_argument("--bucket", type=int, default=50,
                    help="Bucket size in steps for per-50-step perfect bar chart")
    ap.add_argument("--minstep", type=int, default=None)
    ap.add_argument("--maxstep", type=int, default=None)
    args = ap.parse_args()

    ensure_dir(args.outdir)

    # --- Containers
    per_completion = []                           # flat list of completions
    by_step_rewards = defaultdict(list)           # step -> list[reward] (valid only)
    by_step_invalid = Counter()                   # step -> count invalid
    by_step_counts = Counter()                    # step -> total completions
    by_step_nframes = defaultdict(lambda: Counter())  # step -> {3:count,5:count,...}

    # we also want raw rewards per step for the rolling 1.0 plot
    by_step_completions = defaultdict(list)       # step -> list of ALL rewards (valid+invalid but we just check ==1.0)

    # --- Read JSONL
    for row in read_jsonl(args.log):
        step = row.get("step")
        if step is None:
            continue
        if args.minstep is not None and step < args.minstep:
            continue
        if args.maxstep is not None and step > args.maxstep:
            continue

        reward = float(row.get("reward", 0.0))
        is_valid = bool(row.get("is_valid", False))
        n_frames = row.get("n_frames", None)

        per_completion.append({
            "step": step,
            "example_id": row.get("example_id"),
            "gen_idx": row.get("gen_idx"),
            "n_frames": n_frames,
            "reward": reward,
            "is_valid": is_valid,
            "device_rank": row.get("device_rank"),
            "world_size": row.get("world_size"),
            "confidence": row.get("confidence"),
        })

        by_step_counts[step] += 1
        by_step_completions[step].append(reward)

        if is_valid:
            by_step_rewards[step].append(reward)
        else:
            by_step_invalid[step] += 1

        if n_frames is not None:
            by_step_nframes[step][int(n_frames)] += 1

    if not per_completion:
        print("No rows found. Check your log path.")
        return

    # --- Build per-step aggregates
    steps_sorted = sorted(
        set(list(by_step_counts.keys()) + list(by_step_rewards.keys()) + list(by_step_invalid.keys()))
    )

    agg = []
    for s in steps_sorted:
        rewards = by_step_rewards.get(s, [])
        cnt = by_step_counts.get(s, 0)
        inv = by_step_invalid.get(s, 0)
        mean = statistics.fmean(rewards) if rewards else 0.0
        median = statistics.median(rewards) if rewards else 0.0
        # quick quantiles if enough data; else min/max fallback
        if len(rewards) >= 10:
            qs = statistics.quantiles(rewards, n=10)
            p10 = qs[0]
            p90 = qs[-1]
        else:
            p10 = min(rewards) if rewards else 0.0
            p90 = max(rewards) if rewards else 0.0

        inv_rate = (inv / cnt) if cnt > 0 else 0.0
        nfcounts = by_step_nframes.get(s, {})

        agg.append({
            "step": s,
            "count": cnt,
            "valid": len(rewards),
            "invalid": inv,
            "invalid_rate": inv_rate,
            "reward_mean": mean,
            "reward_median": median,
            "reward_p10": p10,
            "reward_p90": p90,
            **{f"count_n{nf}": nfcounts.get(nf, 0) for nf in sorted({3, 5} | set(nfcounts.keys()))}
        })

    # --- Save CSVs
    comp_csv = os.path.join(args.outdir, "per_completion.csv")
    with open(comp_csv, "w", encoding="utf-8") as f:
        cols = ["step", "example_id", "gen_idx", "n_frames", "reward", "is_valid",
                "device_rank", "world_size", "confidence"]
        f.write(",".join(cols) + "\n")
        for r in per_completion:
            f.write(",".join(str(r.get(c, "")) for c in cols) + "\n")

    agg_csv = os.path.join(args.outdir, "per_step.csv")
    with open(agg_csv, "w", encoding="utf-8") as f:
        if agg:
            cols = list(agg[0].keys())
            f.write(",".join(cols) + "\n")
            for r in agg:
                f.write(",".join(str(r.get(c, "")) for c in cols) + "\n")

    print(f"wrote {comp_csv}")
    print(f"wrote {agg_csv}")

    # --- Plot 1: per-completion reward over time
    xs = [r["step"] for r in per_completion]
    ys = [r["reward"] for r in per_completion]
    plt.figure(figsize=(12, 4))
    plt.scatter(xs, ys, s=6, alpha=0.4)
    plt.title("Per-completion reward over time")
    plt.xlabel("Step")
    plt.ylabel("Reward (0..1)")
    plt.grid(True, alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "reward_per_completion.png"), dpi=140)
    plt.close()
    print("wrote reward_per_completion.png")

    # --- Plot 2: per-step aggregates + rolling + invalid
    steps = [r["step"] for r in agg]
    mean = [r["reward_mean"] for r in agg]
    median = [r["reward_median"] for r in agg]
    invrate = [r["invalid_rate"] for r in agg]
    roll = rolling_mean(mean, args.roll) if args.roll and args.roll > 1 else mean

    fig, ax1 = plt.subplots(figsize=(12, 4))
    ax1.plot(steps, mean, label="mean")
    ax1.plot(steps, median, label="median")
    if roll is not mean:
        ax1.plot(steps, roll, label=f"rolling mean (win={args.roll})", linewidth=2)
    ax1.set_xlabel("Step")
    ax1.set_ylabel("Reward (0..1)")
    ax1.set_ylim(-0.05, 1.05)
    ax1.grid(True, alpha=0.25)
    ax1.legend(loc="upper left")

    ax2 = ax1.twinx()
    ax2.plot(steps, invrate, linestyle="--", alpha=0.7, label="invalid rate")
    ax2.set_ylabel("Invalid rate")
    ax2.set_ylim(-0.05, 1.05)
    ax2.legend(loc="upper right")

    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "reward_per_step.png"), dpi=140)
    plt.close()
    print("wrote reward_per_step.png")

    # --- Plot 3: rolling count of perfect completions (reward==1.0)
    win = args.roll if args.roll and args.roll > 1 else 50
    steps_for_bar = []
    counts_100 = []
    for i, s in enumerate(steps_sorted):
        start_idx = max(0, i - win + 1)
        window_steps = steps_sorted[start_idx: i + 1]

        cnt_100 = 0
        for ws in window_steps:
            for rew in by_step_completions.get(ws, []):
                if abs(rew - 1.0) < 1e-6:
                    cnt_100 += 1

        steps_for_bar.append(s)
        counts_100.append(cnt_100)

    plt.figure(figsize=(12, 4))
    plt.bar(steps_for_bar, counts_100, width=1.0)
    plt.title(f"# completions with reward==1.0 in last {win} steps (rolling)")
    plt.xlabel("Step")
    plt.ylabel(f"Count in window ({win} steps)")
    plt.grid(True, axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "perfect_completions_rolling.png"), dpi=140)
    plt.close()
    print("wrote perfect_completions_rolling.png")

    # --- Plot 4: bucketed perfects every N steps (e.g. 50)
    bucket_size = args.bucket
    bucket_perfects = Counter()
    # we’ll bucket by *completion* not by step aggregates, to catch every row
    for r in per_completion:
        b = (r["step"] // bucket_size) * bucket_size
        if abs(r["reward"] - 1.0) < 1e-6:
            bucket_perfects[b] += 1

    bucket_keys = sorted(bucket_perfects.keys())
    bucket_vals = [bucket_perfects[k] for k in bucket_keys]

    plt.figure(figsize=(12, 4))
    plt.bar(bucket_keys, bucket_vals, width=bucket_size * 0.8)
    plt.title(f"# completions with reward==1.0 per {bucket_size}-step bucket")
    plt.xlabel("Step bucket start")
    plt.ylabel("Perfect count in bucket")
    plt.grid(True, axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, f"perfect_completions_bucket_{bucket_size}.png"), dpi=140)
    plt.close()
    print(f"wrote perfect_completions_bucket_{bucket_size}.png")

    # --- Quick last-row print
    if agg:
        last = agg[-1]
        print("\nLatest step summary:")
        for k in [
            "step",
            "count",
            "valid",
            "invalid",
            "invalid_rate",
            "reward_mean",
            "reward_median",
            "reward_p10",
            "reward_p90",
        ]:
            print(f"  {k:>14}: {last[k]}")

    if counts_100:
        print(f"\nmax rolling perfects in window={win}: {max(counts_100)}")
    if bucket_vals:
        print(f"max perfects in any {bucket_size}-step bucket: {max(bucket_vals)}")


if __name__ == "__main__":
    main()