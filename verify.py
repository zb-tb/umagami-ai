#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
指紋の照合（誰でも使える・標準ライブラリだけで動く）

発走前に ledger ブランチへ記録した指紋（sha256）と、結果の後に出した中身（reveals/）が
一致するかを確かめます。

使い方:
  git clone -b ledger https://github.com/<owner>/<repo>.git ledger
  python3 verify.py ledger                 # 全日
  python3 verify.py ledger --date 20261003 # 1日だけ
  python3 verify.py --payload reveal.json  # 開封ファイル（または中身のJSON）のハッシュを出す

指紋の計算:
  中身の JSON を、キーを辞書順に並べ替え、区切りの空白なし（, と :）、非ASCII文字はそのまま
  （ensure_ascii=False）で文字列にし、UTF-8 のバイト列の sha256 を取ります。
  中身に入るのは文字列・整数・真偽・null だけです（小数は入れません）。

1日のまとめ（root）:
  その日の fingerprints/YYYYMMDD.jsonl の sha256 を行の順に並べ、2つずつ
  sha256(左の16進 + 右の16進) を重ねた値です。奇数のときは最後を複製します。

GitHub 側の記録時刻:
  git のコミット日時は書く側が自由に付けられるため、証拠には使いません。
  GitHub が記録した push の時刻は、リポジトリのアクティビティ
  （https://api.github.com/repos/<owner>/<repo>/activity?ref=refs/heads/ledger）で見られます。
  見られる期間には制限があります。
"""
import argparse
import hashlib
import json
import os
import re
import sys

LINE_SCHEMA = "keiba-public-line-v1"
REVEAL_SCHEMA = "keiba-public-reveal-v1"
PAYLOAD_SCHEMA = "keiba-public-v1"


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_hash(payload):
    return sha256_hex(canonical_json(payload))


def merkle_root(leaves):
    if not leaves:
        return sha256_hex("")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(sha256_hex(left + right))
        level = nxt
    return level[0]


def read_lines(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(json.loads(raw))
            except ValueError:
                out.append({"_broken_line": n})
    return out


def verify_day(ledger_dir, ymd):
    """1日分を照合する。結果を dict で返す"""
    lines = read_lines(os.path.join(ledger_dir, "fingerprints", ymd + ".jsonl"))
    reveal_dir = os.path.join(ledger_dir, "reveals", ymd)
    reveals = {}
    if os.path.isdir(reveal_dir):
        for name in sorted(os.listdir(reveal_dir)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(reveal_dir, name), "r", encoding="utf-8") as f:
                doc = json.load(f)
            reveals[doc.get("race_id", name[:-5])] = doc

    rows = []
    leaves = []
    known = set()
    broken = 0
    for line in lines:
        if "_broken_line" in line or not isinstance(line.get("sha256"), str):
            broken += 1
            continue
        sha = line["sha256"]
        race_id = line.get("race_id")
        leaves.append(sha)
        known.add((race_id, sha))
        doc = reveals.get(race_id)
        status = "not_revealed"
        if doc is not None:
            status = "not_in_reveal"
            for v in doc.get("versions", []):
                if v.get("sha256") != sha:
                    continue
                payload = v.get("payload")
                if isinstance(payload, dict) and payload.get("schema") == PAYLOAD_SCHEMA and payload_hash(payload) == sha:
                    status = "match"
                else:
                    status = "mismatch"
                break
        rows.append({"race_id": race_id, "sha256": sha, "status": status})

    orphans = []
    for race_id, doc in reveals.items():
        for v in doc.get("versions", []):
            if (race_id, v.get("sha256")) not in known:
                orphans.append({"race_id": race_id, "sha256": v.get("sha256")})

    counts = {"lines": len(rows), "match": 0, "mismatch": 0, "not_revealed": 0, "not_in_reveal": 0}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "date": ymd,
        "root": merkle_root(leaves),
        "counts": counts,
        "broken_lines": broken,
        "orphan_reveals": orphans,
        "rows": rows,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="指紋の照合（ledger ブランチの fingerprints と reveals を照らし合わせる）")
    ap.add_argument("ledger_dir", nargs="?", help="ledger ブランチを取り出したフォルダ")
    ap.add_argument("--date", help="YYYYMMDD（省略時は全日）")
    ap.add_argument("--payload", help="開封ファイル（reveals/...json）または中身の JSON。ハッシュを出す")
    ap.add_argument("--json", action="store_true", help="結果を JSON で出す")
    ap.add_argument("--strict", action="store_true", help="まだ開封していない指紋があっても失敗にする")
    args = ap.parse_args(argv)

    if args.payload:
        with open(args.payload, "r", encoding="utf-8") as f:
            doc = json.load(f)
        items = []
        if isinstance(doc, dict) and doc.get("schema") == REVEAL_SCHEMA:
            for v in doc.get("versions", []):
                h = payload_hash(v.get("payload"))
                items.append({"version": v.get("version"), "sha256": h, "recorded": v.get("sha256"), "match": h == v.get("sha256")})
        else:
            items.append({"sha256": payload_hash(doc)})
        if args.json:
            print(json.dumps(items, ensure_ascii=False))
        else:
            for it in items:
                print(" ".join("%s=%s" % (k, it[k]) for k in it))
        return 0 if all(it.get("match", True) for it in items) else 1

    if not args.ledger_dir:
        ap.error("ledger_dir か --payload を指定してください")
    fp_dir = os.path.join(args.ledger_dir, "fingerprints")
    if args.date:
        if not re.match(r"^\d{8}$", args.date):
            ap.error("--date は YYYYMMDD")
        days = [args.date]
    else:
        days = sorted(n[:-6] for n in os.listdir(fp_dir) if re.match(r"^\d{8}\.jsonl$", n)) if os.path.isdir(fp_dir) else []

    results = [verify_day(args.ledger_dir, d) for d in days]
    bad = 0
    for r in results:
        c = r["counts"]
        bad += c["mismatch"] + c["not_in_reveal"] + len(r["orphan_reveals"]) + r["broken_lines"]
        if args.strict:
            bad += c["not_revealed"]
    if args.json:
        print(json.dumps({"days": results, "ok": bad == 0}, ensure_ascii=False))
    else:
        for r in results:
            c = r["counts"]
            print("%s 指紋%d件 一致%d 不一致%d 未開封%d 開封に無い%d 台帳に無い開封%d 壊れた行%d root=%s" % (
                r["date"], c["lines"], c["match"], c["mismatch"], c["not_revealed"], c["not_in_reveal"],
                len(r["orphan_reveals"]), r["broken_lines"], r["root"]))
            for row in r["rows"]:
                if row["status"] != "match":
                    print("  %s %s %s" % (row["race_id"], row["sha256"][:12], row["status"]))
        print("OK" if bad == 0 else "NG（%d件）" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
