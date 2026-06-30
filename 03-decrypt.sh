#!/usr/bin/env bash
#
# 03-decrypt.sh — FairPlay 復号ラッパ（field-kit / ipt 非依存・単独持ち出し用）
#
# このスクリプトは「デバイス隣接の Linux/macOS 箱」で動かす想定。
# Windows 母艦の `ipt` には依存しない。出力（復号 IPA + manifest.json）だけを
# 母艦に戻して `ipt init` に投入する、というハンドオフ契約。
#
#   役割: JB 実機の対象アプリを frida-ios-dump / bagbak でメモリダンプ復号し、
#         cryptid=0 を検証して、母艦が機械的に取り込める manifest.json を出力する。
#
#   複数アプリ対応: -b を複数指定するか -f <file> でパッケージ名一覧を渡すと、
#         1 つずつ順番にダンプする。1 アプリの失敗で全体を止めず（best-effort）、
#         最後に成否サマリ（_batch-results.tsv / _batch-summary.json）を出す。
#
# 前提（README で詳述 / 手順は docs/TROUBLESHOOTING.md の「IPA 取得→復号ランブック」）:
#   - 実機が脱獄済み（A11 機なら palera1n）で frida-server 稼働中
#   - 対象アプリがインストール済み（01/02 を踏むか手動で install 済み）
#   - 母艦側 frida と実機 frida-server の **メジャー版が一致**（ズレると頻出故障）
#   - python3 が使えること（frida-ios-dump 自体が python。cryptid 検証もこれで行う）
#
# 依存ツール（いずれか一方の dumper + python3）:
#   - frida-ios-dump (AloneMonkey)  … 既定。`dump.py`
#   - bagbak                         … 代替。`bagbak`
#   - python3                        … cryptid/version/sha256/manifest 生成（標準ライブラリのみ）
#
# 使い方:
#   # 単一
#   ./03-decrypt.sh -b com.example.app
#   ./03-decrypt.sh -b com.example.app -o ./out --dumper bagbak
#   ./03-decrypt.sh -b com.example.app -H 192.168.1.50:27042      # frida リモート
#   FRIDA_IOS_DUMP=/opt/frida-ios-dump/dump.py ./03-decrypt.sh -b com.example.app
#
#   # 複数（-b を繰り返す / ファイルから読む。両方混在も可）
#   ./03-decrypt.sh -b com.a.app -b com.b.app
#   ./03-decrypt.sh -f bundles.txt -o ./out
#   ./03-decrypt.sh -f bundles.txt -b com.extra.app --keep-going
#
#   bundles.txt の書式（1 行 1 パッケージ。# 以降はコメント・空行/CR は無視）:
#     com.example.one
#     com.example.two   # メモも書ける
#     # この行はコメント
#
set -uo pipefail
# 注: per-bundle のソフト失敗継続のため -e は使わない（致命エラーは die で明示停止）。

# ---- 既定値 ----------------------------------------------------------------
BUNDLES=()             # 対象パッケージ（-b 繰り返し / -f ファイル で蓄積）
OUT_DIR="./decrypted-out"
DUMPER="auto"          # auto | frida-ios-dump | bagbak
DUMP_PY="${FRIDA_IOS_DUMP:-}"   # frida-ios-dump の dump.py パス（未指定なら探索）
FRIDA_HOST=""          # 例 192.168.1.50:27042（指定で frida リモート、未指定は USB）
ENCRYPTED_IPA=""       # 任意: 暗号化版 IPA（cryptid before 記録用。無ければ "1(assumed)"）
KEEP_GOING=1           # 1=失敗しても次のバンドルへ（既定）。0=最初の失敗で停止

log()  { printf '\033[36m[decrypt]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[warn]\033[0m %s\n'    "$*" >&2; }
err()  { printf '\033[31m[error]\033[0m %s\n'   "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
  # シェバング直後の連続コメント行をそのままヘルプとして出す（行番号非依存）。
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
  exit "${1:-0}"
}

# ---- bundle ファイル読み込み ------------------------------------------------
read_bundle_file() {
  local f="$1" line
  [[ -f "$f" ]] || die "bundle ファイルが見つからない: $f"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"          # 行コメント除去（bundle id に # は来ない）
    line="${line//$'\r'/}"      # CR 除去（Windows 母艦で編集したファイル対策）
    # 前後の空白を削る
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] || continue
    BUNDLES+=("$line")
  done < "$f"
}

# ---- 引数 ------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--bundle)    [[ $# -ge 2 ]] || die "$1 に値がない"; BUNDLES+=("$2"); shift 2;;
    -f|--file)      [[ $# -ge 2 ]] || die "$1 に値がない"; read_bundle_file "$2"; shift 2;;
    -o|--out)       [[ $# -ge 2 ]] || die "$1 に値がない"; OUT_DIR="$2"; shift 2;;
    --dumper)       [[ $# -ge 2 ]] || die "$1 に値がない"; DUMPER="$2"; shift 2;;
    --dump-path)    [[ $# -ge 2 ]] || die "$1 に値がない"; DUMP_PY="$2"; shift 2;;
    -H|--host)      [[ $# -ge 2 ]] || die "$1 に値がない"; FRIDA_HOST="$2"; shift 2;;
    --encrypted)    [[ $# -ge 2 ]] || die "$1 に値がない"; ENCRYPTED_IPA="$2"; shift 2;;
    --keep-going)   KEEP_GOING=1; shift;;
    --stop-on-error) KEEP_GOING=0; shift;;
    -h|--help)      usage 0;;
    *) die "unknown arg: $1 (--help)";;
  esac
done

# ---- 対象の正規化（重複除去 + 形式チェック） --------------------------------
if [[ ${#BUNDLES[@]} -eq 0 ]]; then
  warn "対象パッケージが無い（-b <bundle> か -f <file> を指定）"
  usage 1
fi

declare -A _seen=()
NORM_BUNDLES=()
for b in "${BUNDLES[@]}"; do
  if [[ ! "$b" =~ ^[A-Za-z0-9._-]+$ ]]; then
    warn "不正なパッケージ名としてスキップ: '$b'（reverse-DNS 形式のみ受理）"
    continue
  fi
  if [[ -n "${_seen[$b]:-}" ]]; then
    warn "重複をスキップ: $b"
    continue
  fi
  _seen[$b]=1
  NORM_BUNDLES+=("$b")
done
BUNDLES=("${NORM_BUNDLES[@]}")
[[ ${#BUNDLES[@]} -gt 0 ]] || die "有効なパッケージが 1 件も無い"

command -v python3 >/dev/null 2>&1 || die "python3 が見つからない（cryptid 検証/manifest に必須）"
mkdir -p "$OUT_DIR" || die "出力先を作成できない: $OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"   # 絶対パス化

log "対象 ${#BUNDLES[@]} 件: ${BUNDLES[*]}"

# ---- frida 疎通の最小確認（バッチ前に 1 回） --------------------------------
# device の足場（ipt device 相当）はまだ別。ここでは復号前提の frida 到達だけ見る。
if command -v frida-ps >/dev/null 2>&1; then
  if [[ -n "$FRIDA_HOST" ]]; then
    frida-ps -H "$FRIDA_HOST" >/dev/null 2>&1 || die "frida-ps -H $FRIDA_HOST 失敗（frida-server/版整合/到達性を確認）"
  else
    frida-ps -U >/dev/null 2>&1 || die "frida-ps -U 失敗（USB 接続/frida-server 稼働/母艦-実機の frida メジャー版一致を確認）"
  fi
  log "frida 疎通 OK"
else
  warn "frida-ps が PATH に無い。dumper 内部の frida に委ねる（疎通未検証）"
fi

# ---- dumper 解決（バッチ前に 1 回） -----------------------------------------
resolve_dumper() {
  if [[ "$DUMPER" == "bagbak" ]]; then
    command -v bagbak >/dev/null 2>&1 || die "bagbak が見つからない"
    echo "bagbak"; return
  fi
  # frida-ios-dump / auto: dump.py を探す
  if [[ -z "$DUMP_PY" ]]; then
    for c in ./dump.py ./frida-ios-dump/dump.py /opt/frida-ios-dump/dump.py "$HOME/frida-ios-dump/dump.py"; do
      [[ -f "$c" ]] && { DUMP_PY="$c"; break; }
    done
  fi
  if [[ -n "$DUMP_PY" && -f "$DUMP_PY" ]]; then
    echo "frida-ios-dump"; return
  fi
  if [[ "$DUMPER" == "auto" ]] && command -v bagbak >/dev/null 2>&1; then
    warn "frida-ios-dump(dump.py) 未検出 → bagbak にフォールバック"
    echo "bagbak"; return
  fi
  die "dumper 未解決。FRIDA_IOS_DUMP=/path/to/dump.py を指定するか --dumper bagbak"
}
ACTIVE_DUMPER="$(resolve_dumper)"
log "dumper = $ACTIVE_DUMPER"

# ---- 1 バンドルの処理 -------------------------------------------------------
# 戻り値: 0=OK / 非0=失敗。失敗理由は BUNDLE_REASON に、成果物は BUNDLE_IPA/BUNDLE_MANIFEST に格納。
# die は使わず return で返す（呼び出し側がバッチ継続を判断する）。
process_bundle() {
  local bundle="$1"
  local raw_ipa="$OUT_DIR/${bundle}.ipa"
  BUNDLE_REASON=""
  BUNDLE_IPA=""
  BUNDLE_MANIFEST=""

  log "── [$bundle] ダンプ開始 ───────────────────────────────"

  # --- ダンプ実行 ---
  case "$ACTIVE_DUMPER" in
    frida-ios-dump)
      local dump_args=("$bundle" -o "$raw_ipa")
      [[ -n "$FRIDA_HOST" ]] && dump_args+=(-H "${FRIDA_HOST%%:*}")
      log "実行: python3 $DUMP_PY ${dump_args[*]}"
      if ! python3 "$DUMP_PY" "${dump_args[@]}"; then
        BUNDLE_REASON="dump_failed (frida-ios-dump 失敗: frida版整合/再起動後の palera1n 当て直し/対象が起動するか を疑う)"
        return 10
      fi
      ;;
    bagbak)
      # 既存 IPA 集合を記録 → bagbak が新規生成した IPA を後で特定
      local before_marker="$OUT_DIR/.bagbak_marker_$$"
      : > "$before_marker"
      log "実行: bagbak -o $OUT_DIR $bundle"
      if ! bagbak -o "$OUT_DIR" "$bundle"; then
        rm -f "$before_marker"
        BUNDLE_REASON="dump_failed (bagbak 失敗)"
        return 10
      fi
      # marker より新しい .ipa を採用（既存ダンプの取り違え防止）
      raw_ipa="$(find "$OUT_DIR" -maxdepth 1 -name '*.ipa' -newer "$before_marker" -print 2>/dev/null \
                 | xargs -r ls -t 2>/dev/null | head -n1 || true)"
      rm -f "$before_marker"
      if [[ -z "$raw_ipa" ]]; then
        # フォールバック: 最新 .ipa
        raw_ipa="$(ls -t "$OUT_DIR"/*.ipa 2>/dev/null | head -n1 || true)"
      fi
      if [[ -z "$raw_ipa" || ! -f "$raw_ipa" ]]; then
        BUNDLE_REASON="no_ipa (bagbak 出力 IPA が見つからない)"
        return 11
      fi
      ;;
    *)
      BUNDLE_REASON="internal_error (未知の dumper: $ACTIVE_DUMPER)"
      return 12
      ;;
  esac

  if [[ ! -f "$raw_ipa" ]]; then
    BUNDLE_REASON="no_ipa (復号 IPA が生成されなかった: $raw_ipa)"
    return 11
  fi
  BUNDLE_IPA="$raw_ipa"
  log "[$bundle] ダンプ完了: $raw_ipa"

  # --- cryptid 検証 + manifest 生成（python・標準ライブラリのみ） ---
  # Mach-O(fat/thin)を直接パースし LC_ENCRYPTION_INFO(_64) の cryptid をスライス毎に確認。
  # rabin2 等に依存しない（新品の *nix 箱でも動くように）。
  log "[$bundle] cryptid 検証 + manifest 生成..."
  DECRYPT_IPA="$raw_ipa" ENCRYPTED_IPA="$ENCRYPTED_IPA" BUNDLE_ID="$bundle" \
  DUMPER_NAME="$ACTIVE_DUMPER" OUT_DIR="$OUT_DIR" \
  python3 - <<'PY'
import os, sys, json, zipfile, struct, hashlib, plistlib, datetime, tempfile, shutil

decrypt_ipa = os.environ["DECRYPT_IPA"]
encrypted_ipa = os.environ.get("ENCRYPTED_IPA") or ""
bundle_id = os.environ["BUNDLE_ID"]
dumper = os.environ["DUMPER_NAME"]
out_dir = os.environ["OUT_DIR"]

MH_MAGIC, MH_CIGAM = 0xfeedface, 0xcefaedfe
MH_MAGIC_64, MH_CIGAM_64 = 0xfeedfacf, 0xcffaedfe
FAT_MAGIC, FAT_CIGAM = 0xcafebabe, 0xbebafeca
FAT_MAGIC_64, FAT_CIGAM_64 = 0xcafebabf, 0xbfbafeca
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2c

CPU_NAMES = {0x0100000c: "arm64", 0x0200000c: "arm64_32", 12: "arm", 0x01000007: "x86_64", 7: "x86"}

def _arch_name(cputype):
    return CPU_NAMES.get(cputype & 0xffffffff, f"cpu:{cputype:#x}")

def _parse_thin(data, off, cputype=None):
    """1つの thin Mach-O ヘッダから (arch, cryptid|None) を返す。"""
    magic = struct.unpack_from(">I", data, off)[0]
    if magic in (MH_MAGIC, MH_MAGIC_64):
        end = ">"
    elif magic in (MH_CIGAM, MH_CIGAM_64):
        end = "<"
    else:
        return None
    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64) or struct.unpack_from(end+"I", data, off)[0] in (MH_MAGIC_64, MH_CIGAM_64)
    cpu = struct.unpack_from(end+"i", data, off+4)[0]
    arch = _arch_name(cpu if cputype is None else cputype)
    ncmds = struct.unpack_from(end+"I", data, off+16)[0]
    hdr = 32 if is64 else 28
    p = off + hdr
    cryptid = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(end+"II", data, p)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cmd,cmdsize,cryptoff,cryptsize,cryptid → cryptid は offset 16
            cryptid = struct.unpack_from(end+"I", data, p+16)[0]
        p += cmdsize
        if cmdsize == 0:
            break
    return (arch, cryptid)

def macho_cryptids(path):
    """fat/thin を問わず [{arch, cryptid, encrypted}] を返す。"""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 8:
        return []
    magic = struct.unpack_from(">I", data, 0)[0]
    slices = []
    if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        end = ">" if magic in (FAT_MAGIC, FAT_MAGIC_64) else "<"
        is64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
        nfat = struct.unpack_from(end+"I", data, 4)[0]
        p = 8
        for _ in range(nfat):
            if is64:
                cputype, _cpusub, offset, size, _align = struct.unpack_from(end+"iiQQQ", data, p)
                p += 40
            else:
                cputype, _cpusub, offset, size, _align = struct.unpack_from(end+"iiIII", data, p)
                p += 20
            r = _parse_thin(data, offset, cputype)
            if r:
                slices.append(r)
    else:
        r = _parse_thin(data, 0)
        if r:
            slices.append(r)
    out = []
    for arch, cid in slices:
        out.append({"arch": arch, "cryptid": cid,
                    "encrypted": bool(cid) if cid is not None else False,
                    "has_encryption_cmd": cid is not None})
    return out

def app_info(ipa_path):
    """IPA から実行ファイルの bytes・Info.plist 主要値を取り出す。"""
    with zipfile.ZipFile(ipa_path) as z:
        names = z.namelist()
        # Payload/<App>.app/Info.plist（ネスト appex は除外＝直下の .app）
        plist_name = None
        for n in names:
            parts = n.split("/")
            if len(parts) == 3 and parts[0] == "Payload" and parts[1].endswith(".app") and parts[2] == "Info.plist":
                plist_name = n; break
        if not plist_name:
            # フォールバック: 最短パスの Info.plist
            cands = [n for n in names if n.endswith(".app/Info.plist")]
            plist_name = min(cands, key=lambda s: s.count("/")) if cands else None
        if not plist_name:
            raise SystemExit("Info.plist が IPA 内に見つからない")
        info = plistlib.loads(z.read(plist_name))
        app_dir = plist_name.rsplit("/", 1)[0]
        exe = info.get("CFBundleExecutable")
        exe_name = app_dir + "/" + exe
        if exe_name not in names:
            raise SystemExit(f"実行ファイルが見つからない: {exe_name}")
        tmp = tempfile.mkdtemp(prefix="machocheck_")
        local = os.path.join(tmp, os.path.basename(exe_name))
        with open(local, "wb") as fo:
            fo.write(z.read(exe_name))
        return info, local, tmp, exe

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# --- 復号後 ---
info, exe_local, tmp, exe_name = app_info(decrypt_ipa)
after = macho_cryptids(exe_local)
shutil.rmtree(tmp, ignore_errors=True)

# --- 復号前（任意） ---
before = None
if encrypted_ipa and os.path.isfile(encrypted_ipa):
    _i, e_local, e_tmp, _e = app_info(encrypted_ipa)
    before = macho_cryptids(e_local)
    shutil.rmtree(e_tmp, ignore_errors=True)

# cryptid!=0 のスライスが残っていれば失敗
still_encrypted = [s for s in after if s.get("cryptid")]

manifest = {
    "schema": "ipt-field-kit/decrypt-manifest@1",
    "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "bundle_id": info.get("CFBundleIdentifier", bundle_id),
    "requested_bundle_id": bundle_id,
    "executable": exe_name,
    "version": {
        "short": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
        "min_os": info.get("MinimumOSVersion"),
    },
    "dumper": dumper,
    "decrypted_ipa": os.path.basename(decrypt_ipa),
    "decrypted_ipa_sha256": sha256(decrypt_ipa),
    "cryptid_before": before if before is not None else "1(assumed; --encrypted 未指定)",
    "cryptid_after": after,
    "decrypt_ok": len(still_encrypted) == 0,
    "still_encrypted_slices": still_encrypted,
    "note": "母艦 ipt init にこの IPA を投入。decrypt_ok=true かつ arm64 slice の cryptid=0 を確認のこと。",
}

mpath = os.path.join(out_dir, os.path.splitext(os.path.basename(decrypt_ipa))[0] + ".manifest.json")
with open(mpath, "w", encoding="utf-8") as f:
    json.dump(manifest, f, ensure_ascii=False, indent=2)

print("---- 復号サマリ ----")
print(f"bundle    : {manifest['bundle_id']}")
print(f"version   : {manifest['version']['short']} ({manifest['version']['build']})")
print(f"executable: {exe_name}")
for s in after:
    flag = "ENCRYPTED" if s.get("cryptid") else "ok(cryptid=0)"
    print(f"  slice {s['arch']:<10} cryptid={s['cryptid']}  {flag}")
print(f"manifest  : {mpath}")
print(f"sha256    : {manifest['decrypted_ipa_sha256']}")

if still_encrypted:
    print("\n[FAIL] cryptid!=0 のスライスが残存。復号が不完全（対象 slice/再ダンプを確認）。", file=sys.stderr)
    sys.exit(2)
print("\n[OK] 復号済み（cryptid=0）。母艦へ IPA + manifest.json を転送して ipt init に投入。")
PY
  local rc=$?
  BUNDLE_MANIFEST="$OUT_DIR/$(basename "${raw_ipa%.*}").manifest.json"
  [[ -f "$BUNDLE_MANIFEST" ]] || BUNDLE_MANIFEST=""

  if [[ $rc -eq 0 ]]; then
    return 0
  elif [[ $rc -eq 2 ]]; then
    BUNDLE_REASON="cryptid_incomplete (cryptid!=0 スライス残存; 再ダンプ/対象 slice を確認)"
    return 2
  else
    BUNDLE_REASON="verify_error (cryptid 検証/manifest 生成に失敗 rc=$rc; IPA 破損/Info.plist 欠落を疑う)"
    return 20
  fi
}

# ---- バッチ実行 -------------------------------------------------------------
RESULTS_TSV="$OUT_DIR/_batch-results.tsv"
{ printf 'bundle\tstatus\treason\tipa\tmanifest\n'; } > "$RESULTS_TSV"

declare -i n_ok=0 n_fail=0 idx=0
total=${#BUNDLES[@]}
OK_LIST=()
FAIL_LIST=()

for bundle in "${BUNDLES[@]}"; do
  idx+=1
  log "##### ($idx/$total) $bundle #####"
  process_bundle "$bundle"
  prc=$?
  if [[ $prc -eq 0 ]]; then
    n_ok+=1
    OK_LIST+=("$bundle")
    printf '%s\tOK\t\t%s\t%s\n' "$bundle" "$BUNDLE_IPA" "$BUNDLE_MANIFEST" >> "$RESULTS_TSV"
    log "[$bundle] ✅ OK"
  else
    n_fail+=1
    FAIL_LIST+=("$bundle")
    printf '%s\tFAIL\t%s\t%s\t%s\n' "$bundle" "${BUNDLE_REASON:-unknown}" "${BUNDLE_IPA:-}" "${BUNDLE_MANIFEST:-}" >> "$RESULTS_TSV"
    err "[$bundle] ❌ FAIL: ${BUNDLE_REASON:-unknown}"
    if [[ $KEEP_GOING -eq 0 ]]; then
      warn "--stop-on-error 指定のため中断（残り $((total - idx)) 件は未処理）"
      break
    fi
    warn "次のバンドルへ続行（--stop-on-error で停止可）"
  fi
done

# ---- バッチ summary JSON 生成 -----------------------------------------------
RESULTS_TSV="$RESULTS_TSV" OUT_DIR="$OUT_DIR" TOTAL="$total" \
N_OK="$n_ok" N_FAIL="$n_fail" PROCESSED="$idx" \
python3 - <<'PY' || warn "batch summary JSON の生成に失敗（_batch-results.tsv は有効）"
import os, json, datetime
tsv = os.environ["RESULTS_TSV"]
rows = []
with open(tsv, encoding="utf-8") as f:
    header = f.readline()
    for line in f:
        parts = line.rstrip("\n").split("\t")
        parts += [""] * (5 - len(parts))
        bundle, status, reason, ipa, manifest = parts[:5]
        rows.append({"bundle": bundle, "status": status, "reason": reason or None,
                     "ipa": ipa or None, "manifest": manifest or None})
summary = {
    "schema": "ipt-field-kit/decrypt-batch@1",
    "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "total": int(os.environ["TOTAL"]),
    "processed": int(os.environ["PROCESSED"]),
    "ok": int(os.environ["N_OK"]),
    "failed": int(os.environ["N_FAIL"]),
    "results": rows,
}
path = os.path.join(os.environ["OUT_DIR"], "_batch-summary.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
print(f"batch summary: {path}")
PY

# ---- 最終サマリ -------------------------------------------------------------
echo                                          >&2
log "════════ バッチ結果 ════════"
log "対象 $total 件 / 処理 $idx 件 → OK=$n_ok  FAIL=$n_fail"
[[ ${#OK_LIST[@]}   -gt 0 ]] && log "  OK  : ${OK_LIST[*]}"
[[ ${#FAIL_LIST[@]} -gt 0 ]] && warn "  FAIL: ${FAIL_LIST[*]}"
log "詳細: $RESULTS_TSV"
log "出力: $OUT_DIR"

if [[ $n_fail -gt 0 ]]; then
  warn "失敗あり。frida 版整合/palera1n 当て直し/対象 slice を確認（README §4.4 / TROUBLESHOOTING）。"
  exit 2
fi
log "全件 OK。母艦へ IPA + manifest.json を転送して ipt init に投入。"
exit 0
