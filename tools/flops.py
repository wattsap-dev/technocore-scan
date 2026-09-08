#!/usr/bin/env python3
"""Count the arithmetic behind a token, from each model's own published config.

Two public sources, both checkable by anyone:

  price         openrouter.ai/api/v1/models                     (live, per token)
  architecture  huggingface.co/<repo>/resolve/main/config.json   (pinned here)

Nothing in this file is measured on hardware. It counts the multiply-accumulates
in one forward pass and calls each one 2 FLOPs, the convention the scaling-law
papers use. Read `flops.html` on what this does not count before quoting it.

Every model is reduced to three coefficients, so the page and this file cannot
drift apart -- both evaluate the same closed form:

    FLOPs(s) = A + B_full * s + B_swa * min(s, W)

  A       matmuls whose cost does not depend on how much context is in front of
          the token: attention projections, MLP or activated experts, LM head
  B_full  attention score/value matmuls in full-attention layers, per token of
          context
  B_swa   the same in sliding-window layers, which stop growing at W

Subcommands:
  build   rebuild data/arch.json from data/hf-configs/ + the live price list
  table   print the price-per-PFLOP table
  show    print the full derivation for one model
"""
import argparse
import json
import math
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CFGS = ROOT / "data" / "hf-configs"
ARCH = ROOT / "data" / "arch.json"
OPENROUTER = "https://openrouter.ai/api/v1/models"


class Unmodelled(Exception):
    """This architecture is not one this file knows how to count."""


# --- the families this file will count -------------------------------------
# Anything not named here is reported as unmodelled rather than guessed at.
DENSE = {"llama", "mistral", "ministral3", "qwen2", "qwen3", "qwen2_5_vl",
         "qwen3_vl_text", "phi3", "granite", "hunyuan_v1_dense", "yasa_model",
         "gemma3_text", "muse_glimmer_text"}
MOE_STD = {"qwen3_moe", "qwen3_vl_moe_text", "mixtral", "gpt_oss"}
MOE_SHARED = {"glm4_moe", "glm4v_moe_text"}          # n_routed / n_shared / first_k_dense_replace
MLA = {"deepseek_v3"}                                # multi-head latent attention


def g(cfg, *names, default=None):
    for n in names:
        v = cfg.get(n)
        if v is not None:
            return v
    return default


def gated_mlp(d, ff):
    """gate_proj + up_proj + down_proj, each d x ff, 2 FLOPs per multiply-add."""
    return 6 * d * ff


def analyse(cfg):
    """Reduce one config.json to (A, B_full, B_swa, W, facts). Raises Unmodelled."""
    inner = cfg.get("text_config") or cfg
    mt = inner.get("model_type") or cfg.get("model_type") or "?"
    if mt not in DENSE | MOE_STD | MOE_SHARED | MLA:
        raise Unmodelled(mt)

    d = g(inner, "hidden_size")
    L = g(inner, "num_hidden_layers")
    V = g(inner, "vocab_size")
    H = g(inner, "num_attention_heads")
    if not all(isinstance(x, int) for x in (d, L, V, H)):
        raise Unmodelled("missing core dims")
    KV = g(inner, "num_key_value_heads", default=H)
    hd = g(inner, "head_dim", "attention_head_dim", default=d // H)

    # ---- attention, per layer ---------------------------------------------
    if mt in MLA:
        qk_n = g(inner, "qk_nope_head_dim")
        qk_r = g(inner, "qk_rope_head_dim")
        vh = g(inner, "v_head_dim")
        kv_lora = g(inner, "kv_lora_rank")
        q_lora = g(inner, "q_lora_rank")
        if None in (qk_n, qk_r, vh, kv_lora):
            raise Unmodelled("incomplete MLA dims")
        qk = qk_n + qk_r
        if q_lora:
            q_proj = 2 * d * q_lora + 2 * q_lora * H * qk
        else:
            q_proj = 2 * d * H * qk
        kv_proj = 2 * d * (kv_lora + qk_r) + 2 * kv_lora * H * (qk_n + vh)
        o_proj = 2 * H * vh * d
        attn_proj = q_proj + kv_proj + o_proj
        attn_per_ctx = 2 * H * qk + 2 * H * vh          # QK^T then AV
        attn_kind = "MLA (q_lora=%s, kv_lora=%s)" % (q_lora, kv_lora)
    else:
        attn_proj = (2 * d * H * hd            # Q
                     + 2 * d * KV * hd         # K
                     + 2 * d * KV * hd         # V
                     + 2 * H * hd * d)         # O
        attn_per_ctx = 4 * H * hd              # QK^T then AV
        attn_kind = "GQA (%d heads / %d kv, head_dim %d)" % (H, KV, hd)

    # ---- which layers stop growing with context ---------------------------
    types = g(inner, "layer_types")
    W = g(inner, "sliding_window") or 0
    if isinstance(types, list) and len(types) == L and W:
        n_swa = sum(1 for t in types if "sliding" in str(t))
    elif W and g(inner, "use_sliding_window") is True:
        n_swa = L                                     # qwen2 style, window on every layer
    else:
        n_swa, W = 0, 0
    n_full = L - n_swa

    # ---- MLP / experts, per layer ------------------------------------------
    ff = g(inner, "intermediate_size")
    if mt in DENSE:
        mlp_total = L * gated_mlp(d, ff)
        moe_note = "dense MLP, ff=%d" % ff
    elif mt in MOE_STD:
        n_exp = g(inner, "num_experts", "num_local_experts")
        topk = g(inner, "num_experts_per_tok", "experts_per_token")
        eff = g(inner, "moe_intermediate_size", default=ff)
        shared_ff = g(inner, "shared_expert_intermediate_size", default=0) or 0
        dense_layers = set(g(inner, "mlp_only_layers", default=[]) or [])
        step = g(inner, "decoder_sparse_step", default=1) or 1
        n_dense = sum(1 for i in range(L) if i in dense_layers or (i + 1) % step != 0)
        n_moe = L - n_dense
        per_moe = topk * gated_mlp(d, eff) + gated_mlp(d, shared_ff) + 2 * d * n_exp
        mlp_total = n_dense * gated_mlp(d, ff) + n_moe * per_moe
        moe_note = "%d of %d layers MoE, %d/%d experts active, expert ff=%d" % (
            n_moe, L, topk, n_exp, eff)
    elif mt in MOE_SHARED:
        n_exp = g(inner, "n_routed_experts")
        topk = g(inner, "num_experts_per_tok")
        n_shared = g(inner, "n_shared_experts", default=0) or 0
        eff = g(inner, "moe_intermediate_size")
        n_dense = g(inner, "first_k_dense_replace", default=0) or 0
        n_moe = L - n_dense
        per_moe = (topk + n_shared) * gated_mlp(d, eff) + 2 * d * n_exp
        mlp_total = n_dense * gated_mlp(d, ff) + n_moe * per_moe
        moe_note = "%d of %d layers MoE, %d routed + %d shared of %d experts, expert ff=%d" % (
            n_moe, L, topk, n_shared, n_exp, eff)
    else:  # MLA family, DeepSeek-style MoE
        n_exp = g(inner, "n_routed_experts")
        topk = g(inner, "num_experts_per_tok")
        n_shared = g(inner, "n_shared_experts", default=0) or 0
        eff = g(inner, "moe_intermediate_size")
        n_dense = g(inner, "first_k_dense_replace", default=0) or 0
        if None in (n_exp, topk, eff):
            raise Unmodelled("incomplete MoE dims")
        n_moe = L - n_dense
        per_moe = (topk + n_shared) * gated_mlp(d, eff) + 2 * d * n_exp
        mlp_total = n_dense * gated_mlp(d, ff) + n_moe * per_moe
        moe_note = "%d of %d layers MoE, %d routed + %d shared of %d experts, expert ff=%d" % (
            n_moe, L, topk, n_shared, n_exp, eff)

    # The LM head runs once per token you are given logits for. In decode that is
    # every token; in prefill an implementation only needs the last position, so
    # a prompt token is `A - lm_head` and a generated token is `A`.
    lm_head = 2 * d * V
    A = L * attn_proj + mlp_total + lm_head
    return {
        "model_type": mt,
        "A": A,
        "lm_head": lm_head,
        "B_full": n_full * attn_per_ctx,
        "B_swa": n_swa * attn_per_ctx,
        "W": W,
        "hidden_size": d, "layers": L, "vocab_size": V,
        "full_attn_layers": n_full, "swa_layers": n_swa,
        "attention": attn_kind, "mlp": moe_note,
        "active_params_derived": A // 2,
    }


def flops(a, s):
    """Forward-pass FLOPs for one token with s tokens of context in front of it."""
    return a["A"] + a["B_full"] * s + a["B_swa"] * min(s, a["W"] or 0)


def request_flops(a, prompt, output):
    """Prefill `prompt` tokens, then generate `output` tokens after them."""
    pre = a["A"] * prompt + a["B_full"] * prompt * (prompt - 1) / 2
    if a["W"]:
        pre += a["B_swa"] * sum(min(s, a["W"]) for s in range(0, prompt, max(1, prompt // 512 or 1))) \
               * (prompt / max(1, len(range(0, prompt, max(1, prompt // 512 or 1)))))
    dec = sum(flops(a, prompt + t) for t in range(output)) if output <= 4096 else \
        output * flops(a, prompt + output / 2)
    return pre, dec


def fetch_prices():
    with urllib.request.urlopen(OPENROUTER, timeout=60) as r:
        return json.load(r)["data"]


# --- subcommands ------------------------------------------------------------
def cmd_build(args):
    """Rebuild data/arch.json from the cached configs and the live price list."""
    models = fetch_prices()
    by_repo = {}
    for m in models:
        if m.get("hugging_face_id"):
            by_repo.setdefault(m["hugging_face_id"], []).append(m["id"])

    out, skipped = {}, {}
    for f in sorted(CFGS.glob("*.json")):
        repo = f.name[:-5].replace("__", "/")
        cfg = json.load(open(f))
        try:
            a = analyse(cfg)
        except Unmodelled as e:
            skipped[repo] = str(e)
            continue
        a["repo"] = repo
        a["config_url"] = "https://huggingface.co/%s/blob/main/config.json" % repo
        a["openrouter_ids"] = sorted(by_repo.get(repo, []))
        # Evaluated here so the page can re-evaluate the same closed form and say
        # out loud whether it got the same answers. A page that agrees with a
        # file you can run is worth more than a page that asks to be believed.
        a["check"] = {str(s): flops(a, s) for s in (0, 1000, 32000, 128000, 1000000)}
        out[repo] = a

    doc = {
        "note": "Architecture only. Prices are fetched live by the page; they are "
                "not stored here, because they change.",
        "source_config": "https://huggingface.co/<repo>/resolve/main/config.json",
        "source_price": OPENROUTER,
        "built_by": "tools/flops.py build",
        "formula": "FLOPs(s) = A + B_full*s + B_swa*min(s,W)",
        "modelled": out,
        "not_modelled": skipped,
    }
    ARCH.write_text(json.dumps(doc, indent=1, sort_keys=True))
    print("%d modelled, %d architectures this file will not guess at" % (len(out), len(skipped)))
    fam = {}
    for r, why in skipped.items():
        fam[why] = fam.get(why, 0) + 1
    for k, v in sorted(fam.items(), key=lambda kv: -kv[1]):
        print("   %-32s %d" % (k, v))
    print("wrote %s" % ARCH)


def cmd_table(args):
    doc = json.load(open(ARCH))
    prices = {m["id"]: m for m in fetch_prices()}
    rows = []
    for repo, a in doc["modelled"].items():
        for mid in a["openrouter_ids"]:
            m = prices.get(mid)
            if not m:
                continue
            po = float(m["pricing"]["completion"])
            if po <= 0:
                continue
            # Never extrapolate a model past the context its provider will accept.
            if (m.get("context_length") or 0) < args.context:
                continue
            f_out = flops(a, args.context)
            rows.append((po / f_out * 1e15, mid, po * 1e6, f_out / 1e9,
                         a["active_params_derived"] / 1e9, repo))
    rows.sort()
    print("context = %s tokens   (price per output token, and the arithmetic behind it)\n"
          % format(args.context, ","))
    print("%-40s %10s %10s %10s %12s" % ("model", "$/Mtok", "GFLOP/tok", "Bactive", "$/PFLOP"))
    print("-" * 88)
    for pf, mid, pm, gf, bp, repo in rows[:args.limit]:
        print("%-40s %10.3f %10.1f %10.1f %12.4f" % (mid[:40], pm, gf, bp, pf))
    print("-" * 88)
    print("%d priced models over %d architectures" % (len(rows), len(doc["modelled"])))


def cmd_show(args):
    doc = json.load(open(ARCH))
    hits = [(r, a) for r, a in doc["modelled"].items() if args.model.lower() in r.lower()]
    if not hits:
        print("no modelled architecture matches %r" % args.model)
        return 1
    for repo, a in hits[:args.limit]:
        print("=" * 72)
        print(repo)
        print("  %s" % a["config_url"])
        print("  type            %s" % a["model_type"])
        print("  attention       %s" % a["attention"])
        print("  MLP             %s" % a["mlp"])
        print("  layers          %d full-attention, %d sliding (window %s)"
              % (a["full_attn_layers"], a["swa_layers"], a["W"] or "-"))
        print("  A               %.3e FLOP   (context-independent)" % a["A"])
        print("  B_full          %.3e FLOP per token of context" % a["B_full"])
        print("  B_swa           %.3e FLOP per token of context, capped at W" % a["B_swa"])
        print("  active params   %.2f B   (= A/2, includes the LM head)"
              % (a["active_params_derived"] / 1e9))
        print()
        for s in (0, 1000, 8000, 32000, 128000, 256000):
            print("    context %7s   %9.1f GFLOP/token   %5.1fx"
                  % (format(s, ","), flops(a, s) / 1e9, flops(a, s) / a["A"]))
    return 0


def cmd_check(args):
    """Test the FLOP model against a number the model authors published themselves.

    A MoE repo named `...-235B-A22B` is telling you it activates 22B parameters
    per token. This file never reads that name -- it derives A from the config
    and reports A/2. If the two agree, the accounting in `analyse` is right for
    that architecture. Dense repos state total parameters the same way.
    """
    import re
    doc = json.load(open(ARCH))
    rows, bad = [], 0
    for repo, a in sorted(doc["modelled"].items()):
        name = repo.split("/")[-1]
        m = re.search(r"[-_](\d+(?:\.\d+)?)B[-_]A(\d+(?:\.\d+)?)B", name, re.I)
        states_active = bool(m)
        claimed = float(m.group(2)) if m else None
        if claimed is None:
            m = re.search(r"[-_](\d+(?:\.\d+)?)B(?![-_]?A\d)", name, re.I)
            claimed = float(m.group(1)) if m else None
        if claimed is None:
            continue
        got = a["active_params_derived"] / 1e9
        err = abs(got - claimed) / claimed
        moe = "MoE" in a["mlp"] or "layers MoE" in a["mlp"]
        # A name like `-235B-A22B` states the active count. A bare `-120b` on a
        # MoE repo states the total, and disagreeing with it is the correct
        # answer, not a failure -- so say which kind of name each one is.
        kind = "active" if states_active else ("total" if moe else "dense")
        rows.append((err, repo, claimed, got, kind))
        if err > 0.15 and kind != "total":
            bad += 1
    rows.sort()
    print("%-46s %9s %9s %7s  %s" % ("repo", "in name", "derived", "diff", "name states"))
    print("-" * 88)
    for err, repo, claimed, got, kind in rows:
        print("%-46s %8.1fB %8.2fB %6.1f%%  %s" % (repo[:46], claimed, got, err * 100, kind))
    print("-" * 88)
    tot = sum(1 for r in rows if r[4] == "total")
    print("%d repos put a parameter count in the name." % len(rows))
    print("%d of them state the count this file derives, and %d land within 15%% of it."
          % (len(rows) - tot, len(rows) - tot - bad))
    print("%d state the total instead, and activate a fraction of it per token." % tot)
    return 1 if bad else 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build").set_defaults(fn=cmd_build)
    t = sub.add_parser("table")
    t.add_argument("--context", type=int, default=8000)
    t.add_argument("--limit", type=int, default=30)
    t.set_defaults(fn=cmd_table)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    s = sub.add_parser("show")
    s.add_argument("model")
    s.add_argument("--limit", type=int, default=3)
    s.set_defaults(fn=cmd_show)
    args = p.parse_args()
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
