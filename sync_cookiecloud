#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
青龙 CookieCloud 同步脚本。
"""

import requests
import os
import sys
import json
import time
from urllib.parse import urljoin
import base64
import hashlib # 需要 hashlib
# 尝试导入 pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("错误：缺少 'pycryptodome' 库。请在 Qinglong 的依赖管理中添加它，或手动安装：pip install pycryptodome")
    sys.exit(1)

# --- 配置区域 ---
# CookieCloud 配置 (从环境变量读取)
COOKIE_CLOUD_HOST_ENV = 'COOKIE_CLOUD_HOST'
COOKIE_CLOUD_UUID_ENV = 'COOKIE_CLOUD_UUID'
COOKIE_CLOUD_PASSWORD_ENV = 'COOKIE_CLOUD_PASSWORD'

# Qinglong API 配置 (从环境变量读取)
QL_URL_ENV = 'QL_URL'
QL_CLIENT_ID_ENV = 'QL_CLIENT_ID'
QL_CLIENT_SECRET_ENV = 'QL_CLIENT_SECRET'

# 新增：同步目标配置 (从环境变量读取，JSON 格式)
# 示例: '[{"domain": "bbs.nga.cn", "env_var": "NGA_MONITOR_COOKIE"}, {"domain": ".example.com", "env_var": "EXAMPLE_COOKIE"}]'
COOKIE_SYNC_TARGETS_ENV = 'COOKIE_SYNC_TARGETS'
# --- 配置区域结束 ---


# --- CookieCloud 解密函数 (完全照搬 decrypt.py 的逻辑) ---
def decrypt_cookiecloud_decrypt_py_style(uuid: str, password: str, base64_ciphertext: str) -> bytes:
    """
    解密 CookieCloud 数据，完全复制用户提供的 decrypt.py 中的逻辑。
    """
    try:
        # 1. 生成 "key" (MD5(uuid-password) 的 hex 前16字符 -> bytes)
        intermediate_key = hashlib.md5(f"{uuid}-{password}".encode('utf-8')
                                      ).hexdigest()[:16].encode('utf-8')

        # 2. Base64 解码并分离 salt 和 ct
        encrypted = base64.b64decode(base64_ciphertext)
        if not encrypted.startswith(b'Salted__'):
             raise ValueError("密文格式错误，缺少 'Salted__' 前缀")
        salt = encrypted[8:16]
        ct = encrypted[16:]

        # 3. 手动实现 EVP_BytesToKey (使用 intermediate_key 和 salt 派生实际 Key/IV)
        key_iv = b""
        prev = b""
        while len(key_iv) < 48: # 需要 48 字节 (32 字节 AES-256 Key + 16 字节 IV)
            m = hashlib.md5()
            m.update(prev + intermediate_key + salt)
            prev = m.digest()
            key_iv += prev

        aes_key = key_iv[:32]
        aes_iv = key_iv[32:48]

        # 4. 创建 AES Cipher (CBC 模式) 并解密
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_padded = cipher.decrypt(ct)

        # 5. 移除 PKCS7 填充
        decrypted = unpad(decrypted_padded, AES.block_size, style='pkcs7')
        return decrypted

    except (ValueError, IndexError, base64.binascii.Error) as e:
        print(f"解密过程中出错 (decrypt.py style): {e}")
        if "Padding is incorrect" in str(e) or "Incorrect padding" in str(e):
             print("提示：'Padding is incorrect' 错误。即使使用了 decrypt.py 的逻辑，仍然失败。请再次检查密码、UUID或密文本身。")
        raise ValueError(f"解密失败 (decrypt.py style): {e}") from e
    except Exception as e:
        print(f"发生未预期的解密错误 (decrypt.py style): {e}")
        import traceback
        traceback.print_exc()
        raise

# --- 通用 Cookie 处理函数 (保持不变) ---
def format_cookies_for_domain(cookie_data_dict: dict, target_domain: str) -> str:
     cookie_pairs = []
     if not cookie_data_dict:
         return ""
     for domain, cookies_list in cookie_data_dict.items():
         if domain.endswith(target_domain) or domain == target_domain.lstrip('.'):
             for cookie_item in cookies_list:
                 if 'name' in cookie_item and 'value' in cookie_item:
                     if cookie_item['name'] and cookie_item['value'] is not None:
                         cookie_pairs.append(f"{cookie_item['name']}={cookie_item['value']}")
     return '; '.join(cookie_pairs)

def fetch_and_decrypt_cookiecloud_data(host: str, uuid: str, password: str) -> dict | None:
    if not all([host, uuid, password]):
        print("错误：CookieCloud 配置不完整 (HOST, UUID, PASSWORD 都需要)")
        return None
    get_url = urljoin(host, f'/get/{uuid}')
    print(f"尝试从 CookieCloud 获取加密数据: {get_url}")
    try:
        response = requests.get(get_url, timeout=20)
        response.raise_for_status()
        data = response.json()
        if 'encrypted' in data and data['encrypted']:
            print("成功获取加密数据，开始解密 (使用 decrypt.py 风格逻辑)...")
            try:
                decrypted_json_bytes = decrypt_cookiecloud_decrypt_py_style(uuid, password, data['encrypted'])
                decrypted_json = decrypted_json_bytes.decode('utf-8')
                decrypted_data = json.loads(decrypted_json)
                if 'cookie_data' in decrypted_data:
                    print("解密成功，获取到 Cookie 数据。")
                    return decrypted_data.get('cookie_data')
                else:
                    print("错误：解密后的数据结构不正确，缺少 'cookie_data' 键。")
                    print(f"解密得到的内容片段: {decrypted_json[:200]}...")
                    return None
            except (json.JSONDecodeError, ValueError) as e:
                print(f"错误：处理 CookieCloud 响应或解密失败: {e}")
                return None
            except UnicodeDecodeError as e:
                print(f"错误：解密后的数据无法解码为 UTF-8: {e}")
                print(f"解密得到的原始字节片段: {decrypted_json_bytes[:100]}...")
                return None
        else:
            print("错误：从 CookieCloud 返回的数据中缺少 'encrypted' 字段或该字段为空。")
            print(f"服务器响应: {data}")
            return None
    except requests.exceptions.Timeout:
        print(f"错误：访问 CookieCloud API 超时 ({get_url})")
        return None
    except requests.exceptions.RequestException as e:
        print(f"错误：访问 CookieCloud API 失败: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"错误：解析从 CookieCloud 服务器获取的初始响应失败: {e}")
        print(f"服务器响应内容片段: {response.text[:200]}...")
        return None
    except Exception as e:
        print(f"错误：获取或处理 CookieCloud 数据时发生未知错误: {e}")
        import traceback
        traceback.print_exc()
        return None

# --- Qinglong API 函数 (保持不变) ---
def get_ql_token(ql_url: str, client_id: str, client_secret: str) -> str | None:
    base_url = ql_url.rstrip('/') + '/'
    token_url = urljoin(base_url, f'open/auth/token?client_id={client_id}&client_secret={client_secret}')
    try:
        print(f"正在获取 Qinglong Token...")
        response = requests.get(token_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get('code') == 200 and data.get('data', {}).get('token'):
            print("成功获取 Qinglong API token。")
            return data['data']['token']
        else:
            print(f"错误：获取 Qinglong token 失败: Code={data.get('code')}, Msg={data.get('message', '未知错误')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"错误：请求 Qinglong token API 失败: {e}")
        return None
    except json.JSONDecodeError:
        print(f"错误：解析 Qinglong token 响应失败 (URL: {token_url})。响应内容: {response.text[:200]}...")
        return None

def find_ql_env_id(ql_url: str, token: str, env_name: str) -> str | None:
    base_url = ql_url.rstrip('/') + '/'
    env_list_url = urljoin(base_url, 'open/envs')
    headers = {'Authorization': f'Bearer {token}'}
    params = {'searchValue': env_name}
    try:
        print(f"正在查找环境变量 '{env_name}'...")
        response = requests.get(env_list_url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get('code') == 200 and 'data' in data:
            envs = data['data']
            found_env = None
            for env in envs:
                if env.get('name') == env_name:
                    found_env = env
                    break
            if found_env:
                # --- 修改以优先使用 'id' ---
                # Qinglong v2.11+ 似乎主要使用 id，旧版可能用 _id
                env_id = found_env.get('id') or found_env.get('_id')
                if env_id:
                    print(f"找到环境变量 '{env_name}' 的 ID: {env_id}")
                    return str(env_id)
                else:
                    print(f"错误：找到环境变量 '{env_name}' 但缺少 ID 字段 ('id' 或 '_id')。")
                    print(f"找到的环境变量数据: {found_env}")
                    return None
            else:
                print(f"警告：未找到名为 '{env_name}' 的环境变量。请先在 Qinglong 中手动创建。")
                return None
        else:
            print(f"错误：获取 Qinglong 环境变量列表失败: Code={data.get('code')}, Msg={data.get('message', '未知错误')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"错误：请求 Qinglong env list API 失败: {e}")
        return None
    except json.JSONDecodeError:
        print(f"错误：解析 Qinglong env list 响应失败 (URL: {env_list_url})。响应内容: {response.text[:200]}...")
        return None

def update_ql_env(ql_url: str, token: str, env_id: str, env_name: str, env_value: str) -> bool:
    base_url = ql_url.rstrip('/') + '/'
    env_update_url = urljoin(base_url, 'open/envs') # 更新通常使用 /open/envs
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    # --- 修改开始 ---
    # 根据之前的错误日志，此版本的青龙需要 'id' 字段来标识要更新的变量
    payload = {
        'name': env_name,
        'value': env_value,
        'remarks': f"由脚本于 {time.strftime('%Y-%m-%d %H:%M:%S')} 自动更新",
        'id': env_id # 将键名从 '_id' 修改为 'id'
    }
    # --- 修改结束 ---
    try:
        print(f"正在更新环境变量 '{env_name}' (ID: {env_id})...")
        # 使用 PUT 方法尝试更新
        response = requests.put(env_update_url, headers=headers, json=payload, timeout=15)

        if response.status_code == 200:
            data = response.json()
            if data.get('code') == 200:
                print(f"成功更新 Qinglong 环境变量 '{env_name}'。")
                return True
            else:
                print(f"错误：更新 Qinglong 环境变量 '{env_name}' 失败 (API 返回 Code={data.get('code')}, Msg={data.get('message', '未知错误')})")
                print(f"失败响应: {response.text}")
                return False
        else:
            # HTTP 请求失败
            print(f"错误：更新 Qinglong 环境变量 '{env_name}' 失败 (HTTP Status Code: {response.status_code})")
            print(f"失败响应: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"错误：请求 Qinglong env update API 失败: {e}")
        if e.response is not None:
            print(f"失败响应详情: Status Code={e.response.status_code}, Body={e.response.text}")
        return False
    except json.JSONDecodeError:
        print(f"错误：解析 Qinglong env update 响应失败 (URL: {env_update_url})。响应内容: {response.text[:200]}...")
        return False

# --- 主逻辑 (保持不变) ---
def main():
    print("-" * 30)
    print("--- 开始执行通用 CookieCloud 同步脚本 (使用 decrypt.py 逻辑 & Correct QL Update ID) ---")
    start_time = time.time()

    # 1. 读取环境变量
    print("读取环境变量配置...")
    cookie_cloud_host = os.environ.get(COOKIE_CLOUD_HOST_ENV)
    cookie_cloud_uuid = os.environ.get(COOKIE_CLOUD_UUID_ENV)
    cookie_cloud_password = os.environ.get(COOKIE_CLOUD_PASSWORD_ENV)
    ql_url = os.environ.get(QL_URL_ENV)
    ql_client_id = os.environ.get(QL_CLIENT_ID_ENV)
    ql_client_secret = os.environ.get(QL_CLIENT_SECRET_ENV)
    sync_targets_json = os.environ.get(COOKIE_SYNC_TARGETS_ENV)

    # 检查基础配置完整性
    required_envs = {
        COOKIE_CLOUD_HOST_ENV: cookie_cloud_host,
        COOKIE_CLOUD_UUID_ENV: cookie_cloud_uuid,
        COOKIE_CLOUD_PASSWORD_ENV: cookie_cloud_password,
        QL_URL_ENV: ql_url,
        QL_CLIENT_ID_ENV: ql_client_id,
        QL_CLIENT_SECRET_ENV: ql_client_secret,
        COOKIE_SYNC_TARGETS_ENV: sync_targets_json,
    }
    missing_envs = [name for name, value in required_envs.items() if not value]
    if missing_envs:
        print(f"错误：缺少以下必要环境变量: {', '.join(missing_envs)}")
        sys.exit(1)

    # 解析同步目标 JSON
    sync_targets = []
    try:
        sync_targets = json.loads(sync_targets_json)
        if not isinstance(sync_targets, list):
            raise ValueError("JSON 顶层结构必须是一个列表")
        for item in sync_targets:
            if not isinstance(item, dict) or 'domain' not in item or 'env_var' not in item:
                raise ValueError("列表中的每个元素必须是包含 'domain' 和 'env_var' 键的字典")
        print(f"解析到 {len(sync_targets)} 个同步目标。")
    except json.JSONDecodeError as e:
        print(f"错误：环境变量 '{COOKIE_SYNC_TARGETS_ENV}' 的 JSON 格式无效: {e}")
        print(f"请确保其值为类似 '[{{\"domain\": \"域名\", \"env_var\": \"变量名\"}}]' 的格式。")
        sys.exit(1)
    except ValueError as e:
        print(f"错误：环境变量 '{COOKIE_SYNC_TARGETS_ENV}' 的 JSON 内容不符合要求: {e}")
        sys.exit(1)

    if not sync_targets:
         print("警告：同步目标列表为空，脚本将不执行任何操作。")
         sys.exit(0)

    # 2. 从 CookieCloud 获取并解密数据 (使用 decrypt.py 逻辑)
    decrypted_cookie_data = fetch_and_decrypt_cookiecloud_data(cookie_cloud_host, cookie_cloud_uuid, cookie_cloud_password)

    if decrypted_cookie_data is None:
        print("未能从 CookieCloud 获取或解密数据，无法继续。")
        sys.exit(1)

    # 3. 获取 Qinglong API Token (只执行一次)
    ql_token = get_ql_token(ql_url, ql_client_id, ql_client_secret)
    if not ql_token:
        print("无法获取 Qinglong API Token，无法更新环境变量。")
        sys.exit(1)

    # 4. 遍历处理每个同步目标
    print("\n--- 开始处理同步目标 ---")
    success_count = 0
    failure_count = 0
    for target in sync_targets:
        target_domain = target['domain']
        target_env_var = target['env_var']
        print(f"\n处理目标: 域名='{target_domain}', 环境变量='{target_env_var}'")

        cookie_string = format_cookies_for_domain(decrypted_cookie_data, target_domain)

        if not cookie_string:
            print(f"警告：未能在 CookieCloud 数据中找到域名 '{target_domain}' 的有效 Cookie。跳过更新 '{target_env_var}'。")
            continue

        target_env_id = find_ql_env_id(ql_url, ql_token, target_env_var)
        if not target_env_id:
            print(f"未能找到环境变量 '{target_env_var}' 的 ID。跳过更新。")
            failure_count += 1
            continue

        update_success = update_ql_env(ql_url, ql_token, target_env_id, target_env_var, cookie_string)
        if update_success:
             success_count += 1
        else:
             failure_count += 1

    # 5. 结束处理
    end_time = time.time()
    duration = end_time - start_time
    print("\n--- 所有同步目标处理完毕 ---")
    print(f"成功更新 {success_count} 个环境变量。")
    print(f"失败或跳过 {failure_count} 个环境变量。")
    print(f"脚本执行总耗时: {duration:.2f} 秒")
    print("-" * 30)

    if failure_count > 0:
        print("脚本执行过程中存在失败项。")
        sys.exit(1)
    else:
        print("脚本执行成功完成。")
        sys.exit(0)

if __name__ == '__main__':
    # 检查 requests 库
    try:
        import requests
    except ImportError:
        print("错误: 缺少 'requests' 库。请安装: pip install requests")
        sys.exit(1)
    # pycryptodome 在脚本开头已检查

    main()
