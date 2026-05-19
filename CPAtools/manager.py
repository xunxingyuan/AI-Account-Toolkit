import os
import sys
import time
import json
import re
import uuid
import random
import string
import secrets
import hashlib
import base64
import threading
import argparse
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass

from curl_cffi import requests

INBOX_DATA = {}
YOUR_DOMAIN = "example.com"


class CFGatewayHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # 仅在需要调试时打印日志
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)

        # 处理来自 Cloudflare 的 Webhook
        if parsed.path == "/webhook":
            try:
                content_length = int(self.headers["Content-Length"])
                post_data = json.loads(self.rfile.read(content_length))

                raw_content = post_data.get("raw", "")
                recipient = post_data.get("to", "").lower().strip()
                sender = post_data.get("from", "").lower().strip()

                # 校验是否来自 OpenAI (发件人或内容包含 openai)
                if "openai" not in sender and "openai" not in raw_content.lower():
                    self._send_json({"status": "ignored"})
                    return

                # 使用 email 库解析邮件
                import email
                from email import policy

                msg = email.message_from_string(raw_content, policy=policy.default)

                def extract_codes(text):
                    if not text:
                        return []
                    # 匹配 6 位数字，排除前后紧邻的数字
                    return re.findall(r"(?<!\d)(\d{6})(?!\d)", text)

                matches = []

                # 遍历邮件的所有部分
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))

                    if (
                        content_type in ["text/plain", "text/html"]
                        and "attachment" not in content_disposition
                    ):
                        payload = part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8", errors="ignore"
                        )

                        # 如果是 HTML，尝试去除标签后再提取
                        if content_type == "text/html":
                            # 简易去标签：将所有标签替换为空格
                            clean_text = re.sub(r"<[^>]+>", " ", payload)
                            matches.extend(extract_codes(clean_text))
                        else:
                            matches.extend(extract_codes(payload))

                # 兜底：如果解析失败，退回到原始正则匹配
                if not matches:
                    matches = extract_codes(raw_content)

                if matches:
                    code = matches[-1]
                    if recipient in INBOX_DATA:
                        INBOX_DATA[recipient]["code"] = code
                        # print(f"[*] [Gateway] 捕获验证码: {code} 来自 {sender} -> {recipient}")

                self._send_json({"status": "ok"})
            except Exception as e:
                print(f"[!] [Gateway] Webhook 处理出错: {e}")
                self._send_json({"status": "error"}, 500)

        # 处理注册逻辑的申请邮箱请求
        elif parsed.path == "/v2/inbox/create":
            email = f"{uuid.uuid4().hex[:10]}@{YOUR_DOMAIN}"
            token = uuid.uuid4().hex
            INBOX_DATA[email] = {"token": token, "code": None, "timestamp": time.time()}
            self._send_json({"address": email, "token": token})

    def do_GET(self):
        # 处理注册逻辑的查验证码请求
        if self.path.startswith("/v2/inbox"):
            params = parse_qs(urlparse(self.path).query)
            token = params.get("token", [""])[0]

            emails_resp = []
            for email, data in INBOX_DATA.items():
                if data["token"] == token and data["code"]:
                    emails_resp.append(
                        {
                            "from": "openai",
                            "subject": "Verification Code",
                            "body": f"Your code is {data['code']}",
                            "date": int(time.time()),
                        }
                    )

            self._send_json({"emails": emails_resp})


def start_gateway_server():
    server = HTTPServer(("0.0.0.0", 8080), CFGatewayHandler)
    server.serve_forever()


CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _generate_password(length: int = 16) -> str:
    special = "!@#$%^&*.-"
    # 确保至少包含每种字符类型各一个
    base = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(special),
    ]
    all_chars = string.ascii_letters + string.digits + special
    base += [secrets.choice(all_chars) for _ in range(length - 4)]
    random.shuffle(base)
    return "".join(base)


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except:
        return {}


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(callback_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for k, v in fragment.items():
        if k not in query:
            query[k] = v
    return {
        "code": (query.get("code", [""])[0] or "").strip(),
        "state": (query.get("state", [""])[0] or "").strip(),
        "error": (query.get("error", [""])[0] or "").strip(),
        "error_description": (query.get("error_description", [""])[0] or "").strip(),
    }


class ChatGPTManager:
    def __init__(self, args):
        self.base_url = args.base_url.rstrip("/")
        self.mgmt_key = args.mgmt_key
        self.target = args.target
        self.check_interval = args.check_interval
        self.reg_delay_min = args.reg_delay_min
        self.reg_delay_max = args.reg_delay_max
        self.proxy = args.proxy

        self.current_reg_delay = random.randint(self.reg_delay_min, self.reg_delay_max)
        self.headers = {
            "Authorization": f"Bearer {self.mgmt_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def log(self, msg):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {msg}")

    def get_remote_accounts(self):
        try:
            url = f"{self.base_url}/v0/management/auth-files"
            resp = requests.get(
                url, headers=self.headers, impersonate="chrome", timeout=20
            )
            if resp.status_code == 200:
                return resp.json().get("files", [])
            return []
        except Exception as e:
            self.log(f"[!] 获取账号列表出错: {e}")
            return []

    def delete_remote_account(self, name):
        try:
            url = f"{self.base_url}/v0/management/auth-files"
            resp = requests.delete(
                url, headers=self.headers, params={"name": name}, impersonate="chrome"
            )
            return resp.status_code in (200, 204)
        except:
            return False

    def check_and_cleanup(self):
        self.log("[*] 开始执行账号健康状态扫描...")
        accounts = self.get_remote_accounts()
        if not accounts:
            return 0

        invalid_count = 0
        for acc in accounts:
            email = acc.get("email")
            auth_index = acc.get("auth_index")
            filename = acc.get("name")
            account_id = acc.get("id_token", {}).get("chatgpt_account_id")

            if not auth_index:
                continue

            payload = {
                "authIndex": auth_index,
                "method": "GET",
                "url": "https://chatgpt.com/backend-api/wham/usage",
                "header": {
                    "Authorization": "Bearer $TOKEN$",
                    "Content-Type": "application/json",
                    "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
                    "Chatgpt-Account-Id": account_id if account_id else "",
                },
            }
            try:
                resp = requests.post(
                    f"{self.base_url}/v0/management/api-call",
                    headers=self.headers,
                    json=payload,
                    impersonate="chrome",
                    timeout=15,
                )
                data = resp.json()
                status = data.get("status_code")
                if not status and "body" in data:
                    try:
                        status = json.loads(data["body"]).get("status")
                    except:
                        pass

                if status == 401:
                    self.log(f"  [-] 账号 {email} 已失效 (401)，正在删除...")
                    if self.delete_remote_account(filename):
                        invalid_count += 1
            except:
                pass

        self.log(f"[+] 扫描完成，共清理 {invalid_count} 个失效账号。")
        return len(accounts) - invalid_count

    def upload_token_data(self, token_json):
        try:
            data = json.loads(token_json)
            email = data.get("email", "unknown")
            filename = f"token_{email.replace('@', '_')}_{int(time.time())}.json"

            url = f"{self.base_url}/v0/management/auth-files?name={filename}"

            resp = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {self.mgmt_key}",
                    "Content-Type": "application/json",
                },
                data=token_json,
                impersonate="chrome",
            )
            return resp.status_code == 200
        except Exception as e:
            self.log(f"[!] 上传 Token 失败: {e}")
            return False

    def register_one(self):
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        s = requests.Session(proxies=proxies, impersonate="chrome")

        email = None
        try:
            # 1. 申请邮箱 (直接调用内存接口)
            email_info = {
                "address": f"{uuid.uuid4().hex[:10]}@{YOUR_DOMAIN}",
                "token": uuid.uuid4().hex,
            }
            email = email_info["address"]
            INBOX_DATA[email] = {
                "token": email_info["token"],
                "code": None,
                "timestamp": time.time(),
            }
            self.log(f"[*] 注册邮箱: {email}")

            # 2. 初始化 OAuth
            state = _random_state()
            code_verifier = _pkce_verifier()
            code_challenge = _sha256_b64url_no_pad(code_verifier)

            params = {
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": DEFAULT_REDIRECT_URI,
                "scope": DEFAULT_SCOPE,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
            }
            auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"

            # 3. 访问并获取 did
            s.get(auth_url, timeout=15)
            did = s.cookies.get("oai-did")
            if not did:
                return None

            # 4. Sentinel
            sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'
            sen_resp = s.post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                headers={
                    "origin": "https://sentinel.openai.com",
                    "content-type": "text/plain;charset=UTF-8",
                },
                data=sen_req_body,
                timeout=15,
            )
            sen_token = sen_resp.json()["token"]
            sentinel = f'{{"p": "", "t": "", "c": "{sen_token}", "id": "{did}", "flow": "authorize_continue"}}'

            # 4b. Sentinel SO Token (用于 create_account 步骤)
            sen_req_body_so = f'{{"p":"","id":"{did}","flow":"oauth_create_account"}}'
            so_token = None
            try:
                sen_resp_so = s.post(
                    "https://sentinel.openai.com/backend-api/sentinel/req",
                    headers={
                        "origin": "https://sentinel.openai.com",
                        "content-type": "text/plain;charset=UTF-8",
                    },
                    data=sen_req_body_so,
                    timeout=15,
                )
                so_token = sen_resp_so.json()["token"]
            except Exception as e:
                self.log(f"[!] 获取 SO sentinel token 失败 (非致命): {e}")

            # 5. Continue
            signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
            cont_resp = s.post(
                "https://auth.openai.com/api/accounts/authorize/continue",
                headers={
                    "openai-sentinel-token": sentinel,
                    "referer": "https://auth.openai.com/create-account",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=signup_body,
            )
            self.log(f"[*] 注册 Continue 状态: {cont_resp.status_code}")
            if cont_resp.text:
                self.log(f"[*] 注册 Continue 响应: {cont_resp.text[:500]}")
            if cont_resp.status_code >= 400:
                self.log(f"[!] 注册 Continue 失败响应: {cont_resp.text[:500]}")

            # 打印当前 cookies 用于诊断
            self.log(f"[*] 当前 Cookies: {dict(s.cookies)}")

            # 6. Password (需要携带 sentinel token，完成设置密码步骤)
            password = _generate_password()
            self.log(f"[*] 生成密码: {password}")
            register_headers = {
                "openai-sentinel-token": sentinel,
                "referer": "https://auth.openai.com/create-account/password",
                "accept": "application/json",
                "content-type": "application/json",
            }
            reg_payload = json.dumps({"password": password, "username": email})
            self.log(f"[*] 注册请求体: {reg_payload}")
            reg_resp = s.post(
                "https://auth.openai.com/api/accounts/user/register",
                headers=register_headers,
                data=reg_payload,
            )
            self.log(f"[*] 密码注册状态: {reg_resp.status_code}")
            self.log(f"[*] 密码注册响应: {reg_resp.text[:500]}")
            if reg_resp.status_code >= 400:
                self.log(f"[!] 密码注册失败，尝试检查 Continue 响应中的流程提示")
                return None

            # 7. Send OTP (GET 请求，复用 register_headers 中的 sentinel token)
            otp_resp = s.get(
                "https://auth.openai.com/api/accounts/email-otp/send",
                headers=register_headers,
                timeout=15,
            )
            self.log(f"[*] 发送验证码状态: {otp_resp.status_code}")
            if otp_resp.text:
                self.log(f"[*] 发送验证码响应: {otp_resp.text[:500]}")
            content_type = otp_resp.headers.get("content-type", "")
            if "text/html" in content_type or otp_resp.text.lstrip().startswith("<!DOCTYPE"):
                self.log("[!] 发送验证码未成功：接口返回的是 HTML 页面，可能是会话状态异常、重定向或风控页面。")
                return None
            if otp_resp.status_code >= 400:
                self.log(f"[!] 发送验证码失败响应: {otp_resp.text[:500]}")
                return None

            # 9. Wait Code
            self.log("[*] 等待验证码...")
            code = None
            for _ in range(30):
                if INBOX_DATA.get(email, {}).get("code"):
                    code = INBOX_DATA[email]["code"]
                    break
                time.sleep(5)

            if not code:
                return None
            self.log(f"[+] 捕获验证码: {code}")

            # 9. Validate (需要携带 sentinel token)
            validate_headers = {
                "openai-sentinel-token": sentinel,
                "accept": "application/json",
                "content-type": "application/json",
                "referer": "https://auth.openai.com/email-verification",
                "origin": "https://auth.openai.com",
            }
            val_resp = s.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=validate_headers,
                data=json.dumps({"code": code}),
            )
            self.log(f"[*] 验证码校验状态: {val_resp.status_code}")
            if val_resp.status_code != 200:
                self.log(f"[!] 校验失败响应: {val_resp.text}")
                return None

            # 10. Create (需要 openai-sentinel-so-token)
            create_headers = {
                "accept": "application/json",
                "content-type": "application/json",
                "referer": "https://auth.openai.com/about-you",
                "origin": "https://auth.openai.com",
            }
            if so_token:
                create_headers["openai-sentinel-so-token"] = so_token
            create_resp = s.post(
                "https://auth.openai.com/api/accounts/create_account",
                headers=create_headers,
                data='{"name":"Neo","birthdate":"2000-02-20"}',
            )
            self.log(f"[*] 账户创建状态: {create_resp.status_code}")

            if create_resp.status_code != 200:
                self.log(f"[!] 账户创建失败详情: {create_resp.text}")
                return None

            # 11. 获取 Workspace ID (三重保险提取法)
            auth_cookie = s.cookies.get("oai-client-auth-session") or ""
            workspace_id = None
            resp_text = create_resp.text

            # 尝试解析 JSON
            try:
                rj = create_resp.json()
                if isinstance(rj, dict):
                    ws_info = rj.get("workspaces") or []
                    if ws_info and isinstance(ws_info, list):
                        workspace_id = ws_info[0].get("id")
                    elif str(rj.get("id", "")).startswith("ws-"):
                        workspace_id = rj.get("id")
            except:
                pass

            # 辅助提取：从 Cookie 字符串正则匹配
            if not workspace_id and auth_cookie:
                ws_match = re.search(r"ws-[a-zA-Z0-9]+", auth_cookie)
                if ws_match:
                    workspace_id = ws_match.group(0)

            # 辅助提取：从 JWT Cookie Payload 提取
            if not workspace_id and auth_cookie:
                for seg in auth_cookie.split("."):
                    try:
                        decoded = _decode_jwt_segment(seg)
                        if isinstance(decoded, dict):
                            ws_list = decoded.get("workspaces") or []
                            if ws_list:
                                workspace_id = ws_list[0].get("id")
                                break
                    except:
                        continue

            if not workspace_id:
                self.log(f"[!] 无法锁定 Workspace ID. 响应长度: {len(resp_text)}")
                if resp_text.strip().startswith("<!DOCTYPE"):
                    self.log("[!] 收到 HTML 响应，可能是被重定向或风控。内容预览:")
                    self.log("-" * 40)
                    self.log(resp_text[:2000])
                    self.log("-" * 40)
                else:
                    self.log(f"[!] 响应内容: {resp_text[:500]}")
                return None

            self.log(f"[*] 锁定 Workspace ID: {workspace_id}")

            select_resp = s.post(
                "https://auth.openai.com/api/accounts/workspace/select",
                headers={
                    "content-type": "application/json",
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "origin": "https://auth.openai.com",
                },
                data=json.dumps({"workspace_id": workspace_id}),
            )

            res_data = select_resp.json()
            continue_url = res_data.get("continue_url")
            self.log(f"[*] 获取 Continue URL 状态: {select_resp.status_code}")
            if not continue_url:
                self.log(f"[!] 缺失 continue_url: {res_data}")
                return None

            # 12. OAuth Chain
            curr_url = continue_url
            for _ in range(6):
                r = s.get(curr_url, allow_redirects=False, timeout=15)
                loc = r.headers.get("Location")
                if not loc:
                    break
                curr_url = urllib.parse.urljoin(curr_url, loc)
                if "code=" in curr_url:
                    cb = _parse_callback_url(curr_url)
                    t_payload = {
                        "grant_type": "authorization_code",
                        "client_id": CLIENT_ID,
                        "code": cb["code"],
                        "redirect_uri": DEFAULT_REDIRECT_URI,
                        "code_verifier": code_verifier,
                    }
                    t_resp = requests.post(
                        TOKEN_URL, data=t_payload, impersonate="chrome"
                    ).json()

                    id_token = t_resp.get("id_token")
                    claims = _jwt_claims_no_verify(id_token)
                    auth_claims = claims.get("https://api.openai.com/auth") or {}

                    config = {
                        "id_token": id_token,
                        "access_token": t_resp.get("access_token"),
                        "refresh_token": t_resp.get("refresh_token"),
                        "account_id": auth_claims.get("chatgpt_account_id"),
                        "email": email,
                        "type": "codex",
                        "expired": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() + int(t_resp.get("expires_in", 0))),
                        ),
                    }
                    return json.dumps(config)

            return None
        except Exception as e:
            self.log(f"[!] 出错: {e}")
            return None
        finally:
            if email and email in INBOX_DATA:
                del INBOX_DATA[email]

    def start(self):
        # 启动邮件网关线程
        threading.Thread(target=start_gateway_server, daemon=True).start()
        self.log("[+] 内存邮件网关已启动 (8080端口)")

        # 打印 Cloudflare Worker 配置提示
        print("\n" + "=" * 60)
        print("提示: 请确保已在 Cloudflare 配置 Email Routing 并绑定以下 Worker:")
        print("-" * 60)
        print(
            """export default {
  async email(message, env, ctx) {
    const rawEmail = await new Response(message.raw).text();
    const vps_url = "http://{您的服务器IP}:8080/webhook";
    await fetch(vps_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to: message.to,
        from: message.from,
        raw: rawEmail
      })
    });
  }
};"""
        )
        print("=" * 60 + "\n")

        last_check_time = 0
        while True:
            now = time.time()
            if now - last_check_time >= self.check_interval:
                current_count = self.check_and_cleanup()
                last_check_time = now
            else:
                current_count = len(self.get_remote_accounts())

            self.log(f"[*] 当前存量: {current_count} / 目标: {self.target}")

            if current_count < self.target:
                token_json = self.register_one()
                if token_json and self.upload_token_data(token_json):
                    self.log("[+] 注册成功并已上传")
                    self.current_reg_delay = random.randint(
                        self.reg_delay_min, self.reg_delay_max
                    )
                else:
                    self.log("[!] 注册失败，退避等待")
                    self.current_reg_delay = min(self.current_reg_delay * 2, 3600)

                time.sleep(self.current_reg_delay)
            else:
                time.sleep(60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ChatGPT 账号全自动管理脚本 (单一脚本版)"
    )
    parser.add_argument(
        "--base-url", default="http://localhost:8317", help="CLIProxyAPI 地址"
    )
    parser.add_argument("--mgmt-key", required=True, help="管理密钥")
    parser.add_argument("--target", type=int, default=100, help="账号目标数量")
    parser.add_argument("--check-interval", type=int, default=3600, help="检测间隔")
    parser.add_argument("--reg-delay-min", type=int, default=60, help="最小延迟")
    parser.add_argument("--reg-delay-max", type=int, default=120, help="最大延迟")
    parser.add_argument("--proxy", default=None, help="代理")
    parser.add_argument("--domain", default="example.com", help="邮箱域名")

    args = parser.parse_args()

    # 更新全局域名变量
    YOUR_DOMAIN = args.domain

    try:
        ChatGPTManager(args).start()
    except KeyboardInterrupt:
        print("\n[*] 已停止。")
