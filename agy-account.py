#!/usr/bin/env python3
# agy-account.py - Antigravity 账号快切(Windows)
#
# 原理:Antigravity 的登录态存在 Windows 凭据管理器的 gemini:antigravity 条目里
#      (DPAPI 加密,绑定当前 Windows 用户)。本脚本把该二进制 blob 导出成文件,
#      切换时写回,等价于 Codex 里换 auth.json,但对象是凭据条目而不是文件。
#
# 用法:
#   python agy-account.py list                列出已保存账号
#   python agy-account.py current             显示当前登录态(邮箱 + blob 指纹)
#   python agy-account.py save work           保存当前登录态为 work
#   python agy-account.py use work            切到 work(要求 Antigravity 已退出)
#   python agy-account.py use work --restart  切到 work:先关 App 再写凭据,最后重开
#   python agy-account.py use -               切回上一个账号
#   python agy-account.py remove work         删除已保存账号
#
# 存储:~/.gemini/auth_profiles/<label>/{wincred.bin,meta.json}
# 注意:blob 经过 DPAPI 加密,只能同一 Windows 用户在同一台机器上还原;
#      备份文件含完整登录凭证,不要上传到任何地方。

import argparse
import ctypes
import ctypes.wintypes
import datetime
import hashlib
import json
import os
import subprocess
import sys
import time

CRED_TARGET = "gemini:antigravity"
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2

# 必须用 use_last_error=True 加载,否则 ctypes.get_last_error() 拿不到真实 Win32 错误码
ADV = ctypes.WinDLL("advapi32", use_last_error=True)
_last_win_error = 0

# 让中文输出在 cmd(代码页 65001)里正常显示,不会因编码报错中断
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HOME = os.path.expanduser("~")
STORE = os.path.join(HOME, ".gemini", "auth_profiles")
APP_STORAGE = os.path.join(os.environ.get("APPDATA", ""), "Antigravity", "app_storage.json")
APP_EXE = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "antigravity", "Antigravity.exe")


# ---------------------------------------------------------------- wincred

class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.wintypes.LPWSTR),
        ("Comment", ctypes.wintypes.LPWSTR),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.wintypes.BYTE)),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.wintypes.LPWSTR),
        ("UserName", ctypes.wintypes.LPWSTR),
    ]


class _CREDENTIAL_W(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.wintypes.LPWSTR),
        ("Comment", ctypes.wintypes.LPWSTR),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.c_char_p),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.wintypes.LPWSTR),
        ("UserName", ctypes.wintypes.LPWSTR),
    ]


def cred_read():
    """返回 (blob, username);没有条目时返回 (None, None)。"""
    ptr = ctypes.POINTER(_CREDENTIAL)()
    if not ADV.CredReadW(CRED_TARGET, CRED_TYPE_GENERIC, 0, ctypes.byref(ptr)):
        return None, None
    try:
        c = ptr.contents
        blob = bytes(c.CredentialBlob[: c.CredentialBlobSize]) if c.CredentialBlobSize else b""
        return blob, c.UserName
    finally:
        ADV.CredFree(ptr)


def win_error():
    return ctypes.WinError(_last_win_error)


def cred_write(blob, username="antigravity"):
    global _last_win_error
    c = _CREDENTIAL_W()
    c.Type = CRED_TYPE_GENERIC
    c.TargetName = CRED_TARGET
    c.UserName = username
    c.CredentialBlob = blob
    c.CredentialBlobSize = len(blob)
    c.Persist = CRED_PERSIST_LOCAL_MACHINE
    ok = bool(ADV.CredWriteW(ctypes.byref(c), 0))
    if not ok:
        _last_win_error = ctypes.get_last_error()
    return ok


# ---------------------------------------------------------------- helpers

def fingerprint(blob):
    return hashlib.sha256(blob).hexdigest()[:12] if blob else "-"


def active_email():
    """从 app_storage.json 读最后一次登录的邮箱;读不到就返回 None。"""
    try:
        with open(APP_STORAGE, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("agy.onboarding.lastLoginUsername")
    except Exception:
        return None


def ensure_store():
    os.makedirs(STORE, exist_ok=True)


def load_profiles():
    ensure_store()
    out = []
    for name in sorted(os.listdir(STORE)):
        d = os.path.join(STORE, name)
        meta_path = os.path.join(d, "meta.json")
        blob_path = os.path.join(d, "wincred.bin")
        if not os.path.isdir(d):
            continue
        meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                pass
        out.append(
            {
                "label": name,
                "email": meta.get("email") or "-",
                "cred_user": meta.get("cred_user") or "",
                "saved_at": meta.get("saved_at") or "-",
                "fingerprint": meta.get("fingerprint") or "-",
                "size": os.path.getsize(blob_path) if os.path.exists(blob_path) else 0,
                "blob_path": blob_path,
            }
        )
    return out


def find_profile(key):
    profiles = load_profiles()
    for p in profiles:
        if p["label"].lower() == key.lower():
            return p
    for p in profiles:
        if str(p["email"]).lower() == key.lower():
            return p
    for p in profiles:
        if str(p["email"]).lower().startswith(key.lower()):
            return p
    return None


def _read_state():
    path = os.path.join(STORE, ".state.json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _write_state(**kw):
    state = _read_state()
    state.update(kw)
    with open(os.path.join(STORE, ".state.json"), "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def set_previous(label):
    _write_state(previous=label)


def get_previous():
    return _read_state().get("previous")


def set_active(label):
    """记录本工具最后一次切换到的账号,作为 App 不回写邮箱时的兜底。"""
    _write_state(active=label)


def get_active():
    return _read_state().get("active")


def refresh_profile_slot(profile, blob, user):
    """把凭据里此刻最新的 blob 回写进该账号的槽位。

    App 大约每小时刷新 token,blob 会变但账号不变;槽位里若一直留着
    save 那一刻的旧 refresh token,下次切回来可能被判失效而要求重新登录。
    每次切走前同步一次,槽位就永远是"这个账号最新的凭证"。
    """
    if not blob or not profile:
        return
    fp = fingerprint(blob)
    if fp == profile["fingerprint"]:
        return
    d = os.path.dirname(profile["blob_path"])
    try:
        with open(profile["blob_path"], "wb") as f:
            f.write(blob)
        meta = {}
        meta_path = os.path.join(d, "meta.json")
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                pass
        meta.update(
            {
                "label": profile["label"],
                "fingerprint": fp,
                "size": len(blob),
                "saved_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                "refreshed_at": datetime.datetime.now().isoformat(timespec="seconds"),
                "cred_user": user or meta.get("cred_user") or "antigravity",
            }
        )
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        print(f"  - 已把最新 token 同步回槽位 {profile['label']}(指纹 {profile['fingerprint']} → {fp})")
    except OSError as e:
        print(f"  ! 同步槽位 {profile['label']} 失败:{e}(不影响本次切换)")


def acquire_lock(stale_sec=120):
    """防双击/并发:同一时刻只允许一个实例改凭据。返回锁文件路径或 None。"""
    ensure_store()
    path = os.path.join(STORE, ".lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return path
    except FileExistsError:
        try:
            if time.time() - os.path.getmtime(path) > stale_sec:
                os.remove(path)
                return acquire_lock(stale_sec)
        except OSError:
            pass
        return None
    except OSError:
        return None


def release_lock(path):
    if path:
        try:
            os.remove(path)
        except OSError:
            pass


PROC_IMAGES = ("antigravity.exe", "language_server")


def procs_running():
    """Antigravity 或 language_server 是否还在跑(两者都查,缺一不可)。"""
    try:
        out = subprocess.run(
            ["tasklist", "/NH"], capture_output=True, text=True, errors="replace"
        ).stdout.lower()
    except Exception:
        return False
    return any(name in out for name in PROC_IMAGES)


def kill_app():
    """关闭 Antigravity 及其 language_server 子进程,等它们真正退出。

    先温和关闭(taskkill 不带 /F,给 App 机会保存会话、把最新 token 刷进凭据),
    超时再强杀;两种方式都轮询确认 Antigravity.exe 和 language_server 全部退出,
    之后凭据管理器才不会再被它们改写。
    """
    if not procs_running():
        return True
    subprocess.run(["taskkill", "/IM", "Antigravity.exe"], capture_output=True)
    deadline = time.time() + 6.0
    while time.time() < deadline and procs_running():
        time.sleep(0.25)
    if procs_running():
        subprocess.run(["taskkill", "/IM", "Antigravity.exe", "/T", "/F"], capture_output=True)
        subprocess.run(["taskkill", "/IM", "language_server.exe", "/T", "/F"], capture_output=True)
        deadline = time.time() + 12.0
        while time.time() < deadline and procs_running():
            time.sleep(0.25)
    return not procs_running()


def start_app():
    if not os.path.exists(APP_EXE):
        print(f"  ! 找不到 {APP_EXE},请手动启动 Antigravity。")
        return False
    os.startfile(APP_EXE)
    return True


def auto_label():
    """自动起一个账号名:优先用邮箱前缀,否则 acc1/acc2..."""
    email = (active_email() or "").strip()
    if "@" in email:
        return email.split("@")[0]
    existing = {p["label"] for p in load_profiles()}
    n = 1
    while f"acc{n}" in existing:
        n += 1
    return f"acc{n}"


def resolve_current(profiles, blob):
    """判定当前生效的是哪个已保存账号,返回 (下标, 判据) 或 (None, None)。

    优先级:
      1. blob 指纹精确命中 —— 凭据里的字节和某个已保存账号完全一致,最硬的证据;
      2. 上次切换记录 —— App 刷新 token 后指纹会变、账号没变,而我们写回时
         校验过指纹,记录比 App 回写的 lastLoginUsername 可信;
      3. 邮箱命中 —— 没有切换记录时的兜底(例如刚装好工具);
      4. 都没命中才算"未保存过"。
    """
    fp = fingerprint(blob)
    for i, p in enumerate(profiles):
        if p["fingerprint"] == fp:
            return i, "指纹"
    last = get_active()
    if last:
        for i, p in enumerate(profiles):
            if p["label"] == last:
                return i, "切换记录"
    email = (active_email() or "").strip().lower()
    if email:
        for i, p in enumerate(profiles):
            if str(p["email"]).strip().lower() == email:
                return i, "邮箱"
    return None, None


# ---------------------------------------------------------------- commands

def cmd_current(_args):
    blob, user = cred_read()
    if blob is None:
        print("未找到凭据条目 gemini:antigravity(可能未登录)。")
        return 1
    print(f"凭据条目 : {CRED_TARGET}")
    print(f"用户名   : {user}")
    print(f"blob 大小: {len(blob)} 字节")
    print(f"blob 指纹: {fingerprint(blob)}")
    print(f"最后登录 : {active_email() or '(读不到)'}")
    profiles = load_profiles()
    current, why = resolve_current(profiles, blob)
    mark = f"{profiles[current]['label']}(按{why})" if current is not None else "(未保存过)"
    print(f"匹配配置 : {mark}")
    return 0


def cmd_list(_args):
    blob, _ = cred_read()
    cur_fp = fingerprint(blob)
    profiles = load_profiles()
    if not profiles:
        print("还没有保存任何账号。先登录一个账号,再执行: python agy-account.py save <名字>")
        return 0
    print(f"{'标记':<4}{'名称':<14}{'邮箱':<32}{'保存时间':<20}{'大小':>7}")
    print("-" * 80)
    for p in profiles:
        mark = "*" if p["fingerprint"] == cur_fp else " "
        print(
            f"{mark:<4}{p['label']:<14}{str(p['email']):<32}{str(p['saved_at']):<20}{p['size']:>7}"
        )
    print("\n* = 当前生效的账号")
    return 0


def cmd_save(args):
    blob, user = cred_read()
    if blob is None:
        print("未找到凭据条目 gemini:antigravity,请先在 Antigravity 里登录。")
        return 1
    email = (active_email() or "").strip()
    fp = fingerprint(blob)
    # 同一账号(指纹相同,或邮箱相同)重复保存时覆盖原有槽位,不产生重复项
    label = args.label
    if not label:
        for p in load_profiles():
            if p["fingerprint"] == fp or (
                email and str(p["email"]).strip().lower() == email.lower()
            ):
                label = p["label"]
                break
    if not label:
        label = auto_label()
    d = os.path.join(STORE, label)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "wincred.bin"), "wb") as f:
        f.write(blob)
    meta = {
        "label": label,
        "email": email,
        "cred_user": user,
        "saved_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "fingerprint": fp,
        "size": len(blob),
    }
    with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"[OK] 已保存账号 {label}({meta['email'] or '邮箱未知'},{len(blob)} 字节)")
    total = len(load_profiles())
    print(f"     当前共 {total} 个已保存账号。")
    if total < 2:
        print("     提示:去 Antigravity 里退出登录,换另一个 Google 账号登录,再双击一次 saveaccount.cmd。")
    return 0


def cmd_cycle(args):
    """一键循环切换:关 App -> 同步旧槽位 -> 写下一个账号 -> 校验 -> 重开 App。"""
    profiles = load_profiles()
    if not profiles:
        print("还没有保存任何账号。")
        print("请先登录一个账号,双击 saveaccount.cmd 把它存下来。")
        return 1
    if len(profiles) == 1:
        print(f"目前只保存了 1 个账号:{profiles[0]['label']}({profiles[0]['email'] or '邮箱未知'})")
        print("切换需要至少 2 个。请先在 Antigravity 里退出登录、换第二个 Google 账号登录,")
        print("再双击一次 saveaccount.cmd 保存它,之后就能一键互切了。")
        return 1

    blob, user = cred_read()
    idx, why = resolve_current(profiles, blob)

    if procs_running():
        print("  - 关闭 Antigravity ...")
        if not kill_app():
            print("  ! 关闭失败,请手动退出 Antigravity 后重试。")
            return 1
        # App 退出瞬间可能刷新过 token,重读最新 blob
        blob, user = cred_read()
        if not (idx is not None and why == "指纹"):
            # 关闭前没有指纹级证据,用最新 blob 再判定一次(可能这次指纹命中)
            idx, why = resolve_current(profiles, blob)

    if idx is None:
        print("  ! 当前登录的账号还没保存过,本次切到第一个已保存账号。")
        cur_label = "(未保存)"
        target = profiles[0]
    else:
        # 切走前把凭据里最新的 blob 回写进当前槽位,防止槽位 token 过期
        refresh_profile_slot(profiles[idx], blob, user)
        cur_label = profiles[idx]["label"]
        target = profiles[(idx + 1) % len(profiles)]
        set_previous(cur_label)

    print(f"  当前账号: {cur_label}" + (f"(判定依据: {why})" if why else ""))
    print(f"  目标账号: {target['label']}({target['email'] or '邮箱未知'})")

    if not os.path.exists(target["blob_path"]):
        print(f"  ! {target['label']} 缺少 wincred.bin,请重新保存该账号。")
        start_app()
        return 1
    with open(target["blob_path"], "rb") as f:
        new_blob = f.read()

    ok = False
    for attempt in range(3):
        if cred_write(new_blob, target.get("cred_user") or user or "antigravity"):
            ok = True
            break
        print(f"  - 写入失败,重试 {attempt + 1}/3 ...")
        time.sleep(1.5)
    if not ok:
        print(f"[FAIL] 写入凭据失败:{win_error()}。")
        start_app()
        return 1

    chk, _ = cred_read()
    if fingerprint(chk) != fingerprint(new_blob):
        print("[FAIL] 写回后校验不一致,未切换成功。")
        start_app()
        return 1

    print(f"  - 凭据已切换并校验通过({len(new_blob)} 字节)")
    set_active(target["label"])
    print("  - 启动 Antigravity ...")
    start_app()
    print()
    print(f"[OK] 已切换到 {target['label']}({target['email'] or '邮箱未知'})")
    return 0



def cmd_use(args):
    key = args.label
    if key == "-":
        key = get_previous()
        if not key:
            print("没有上一个账号记录。")
            return 1
        print(f"切回上一个账号: {key}")
    p = find_profile(key)
    if not p:
        print(f"找不到账号 {key},先跑 list 看看。")
        return 1
    if not os.path.exists(p["blob_path"]):
        print(f"{p['label']} 缺少 wincred.bin,请重新 save 一次。")
        return 1

    # App 运行时写凭据会被它内存里的旧 token 覆盖回去,必须先关掉
    running = procs_running()
    if running and not args.restart:
        print("[FAIL] Antigravity 正在运行,直接写凭据会被它覆盖。")
        print("       请加 --restart(自动关 App 再切换),或先手动完全退出 Antigravity。")
        return 1

    blob, user = cred_read()
    old_fp = fingerprint(blob)
    if old_fp == p["fingerprint"]:
        print(f"当前已经是 {p['label']},无需切换。")
        return 0

    if running:
        print("  - 关闭 Antigravity ...")
        if not kill_app():
            print("  ! 关闭失败,请手动退出后重试。")
            return 1
        # 退出瞬间可能刷新过 token,重读
        blob, user = cred_read()

    # 记录切换前的账号,并把它最新的 blob 回写进旧槽位
    profiles = load_profiles()
    old_idx = None
    for i, q in enumerate(profiles):
        if q["fingerprint"] == old_fp:
            old_idx = i
            break
    if old_idx is None:
        last = get_active()
        for i, q in enumerate(profiles):
            if q["label"] == last:
                old_idx = i
                break
    if old_idx is not None:
        set_previous(profiles[old_idx]["label"])
        refresh_profile_slot(profiles[old_idx], blob, user)

    with open(p["blob_path"], "rb") as f:
        new_blob = f.read()
    ok = False
    for attempt in range(3):
        if cred_write(new_blob, p.get("cred_user") or user or "antigravity"):
            ok = True
            break
        print(f"  - 写入失败,重试 {attempt + 1}/3 ...")
        time.sleep(1.5)
    if not ok:
        print(f"[FAIL] 写入凭据失败:{win_error()}。")
        if args.restart or running:
            start_app()
        return 1

    chk, _ = cred_read()
    if fingerprint(chk) != fingerprint(new_blob):
        print("[FAIL] 写回后校验不一致,未切换成功。")
        if args.restart or running:
            start_app()
        return 1

    print(f"[OK] 凭据已写回: {p['label']}({p['email'] or '邮箱未知'})")
    set_active(p["label"])

    if args.restart:
        print("  - 启动 Antigravity ...")
        start_app()
        print("[OK] 已重启 Antigravity,应已是新账号。")
    else:
        print("提示:启动 Antigravity 后生效。")
    return 0


def cmd_remove(args):
    p = find_profile(args.label)
    if not p:
        print(f"找不到账号 {args.label}")
        return 1
    blob, _ = cred_read()
    if p["fingerprint"] == fingerprint(blob):
        print("这是当前生效的账号,先切到别的账号再删。")
        return 1
    import shutil

    shutil.rmtree(os.path.dirname(p["blob_path"]), ignore_errors=True)
    print(f"[OK] 已删除 {p['label']}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Antigravity 账号快切(基于 Windows 凭据管理器 gemini:antigravity)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
        "  python agy-account.py save work\n"
        "  python agy-account.py use work --restart\n"
        "  python agy-account.py use -\n",
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("current", help="显示当前登录态")
    sub.add_parser("list", help="列出已保存账号")
    sp = sub.add_parser("save", help="保存当前登录态")
    sp.add_argument("label", nargs="?", help="账号名,省略则自动命名(邮箱前缀 / acc N)")
    up = sub.add_parser("use", help="切换到指定账号")
    up.add_argument("label", help="账号名/邮箱/前缀,或 - 表示上一个")
    up.add_argument("--restart", action="store_true", help="切换后自动重启 Antigravity")
    sub.add_parser("cycle", help="一键循环切换到下一个账号(自动关/开 App)")
    rp = sub.add_parser("remove", help="删除已保存账号")
    rp.add_argument("label")
    args = ap.parse_args()

    handlers = {
        "current": cmd_current,
        "list": cmd_list,
        "save": cmd_save,
        "use": cmd_use,
        "cycle": cmd_cycle,
        "remove": cmd_remove,
    }
    if not args.cmd:
        ap.print_help()
        return 0
    lock = None
    if args.cmd in ("save", "use", "cycle"):
        lock = acquire_lock()
        if not lock:
            print("另一个 agy-account 实例正在运行,请等它结束后再试。")
            return 1
    try:
        return handlers[args.cmd](args)
    finally:
        release_lock(lock)


if __name__ == "__main__":
    sys.exit(main())
