import asyncio
import aiohttp
import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from collections import Counter, defaultdict
import base64
import time
import logging
from typing import Dict, List, Optional, Any
from geopy.geocoders import Nominatim
import uuid
import random
import os
import sqlite3

Arthn_ua = UserAgent()
hashtag_fetch_count = 0
logging.basicConfig(level=logging.INFO, format='\033[1;94m%(asctime)s - %(levelname)s - %(message)s\033[0m')
logger = logging.getLogger('ArthnOSINT')

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.instagram.com/",
}
LOGIN_URL = "https://www.instagram.com/accounts/login/ajax/"
WEB_PROFILE_API = "https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
ABOUT_URLS = [
    "https://www.instagram.com/{username}/about/",
    "https://www.instagram.com/{username}/about_this_account/"
]
TARGET_DIR = os.path.expanduser("~/instatools")
SESSION_FILE = os.path.join(TARGET_DIR, "instagram_session.json")

def save_session(session: requests.Session, path: str):
    cookies = {c.name: c.value for c in session.cookies}
    data = {"cookies": cookies, "headers": dict(session.headers)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_session(path: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS_BASE)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ck = data.get("cookies", {})
            for k, v in ck.items():
                s.cookies.set(k, v)
            h = data.get("headers", {})
            if h:
                s.headers.update(h)
        except Exception:
            pass
    return s

def interactive_login(session: requests.Session, username: str, password: str) -> dict:
    r = session.get("https://www.instagram.com/accounts/login/", headers=HEADERS_BASE, timeout=15)
    csrf = session.cookies.get("csrftoken") or session.cookies.get("csrf_token")
    if not csrf:
        soup = BeautifulSoup(r.text, "lxml")
        m = soup.find("meta", {"name": "csrf-token"}) or soup.find("meta", {"name": "csrfmiddlewaretoken"})
        if m and m.get("content"):
            csrf = m["content"]
    if not csrf:
        m = re.search(r"csrf_token\\\":\\\"(.*?)\\\"", r.text)
        if m:
            csrf = m.group(1)
    if csrf:
        session.headers.update({"X-CSRFToken": csrf, "X-Requested-With": "XMLHttpRequest"})
    else:
        session.headers.update({"X-Requested-With": "XMLHttpRequest"})

    enc = f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}"
    payload = {"username": username, "enc_password": enc, "queryParams": "{}", "optIntoOneTap": "false"}
    resp = session.post(LOGIN_URL, data=payload, headers=session.headers, allow_redirects=True, timeout=15)
    try:
        j = resp.json()
    except Exception:
        j = {"status": "fail", "raw": resp.text}

    if "csrf_token" in session.cookies:
        session.headers.update({"X-CSRFToken": session.cookies.get("csrf_token")})
    if session.cookies.get("csrftoken"):
        session.headers.update({"X-CSRFToken": session.cookies.get("csrftoken")})
    return j

def ensure_logged_in(session: requests.Session) -> (bool, str):
    if os.path.isfile(SESSION_FILE):
        logger.info("[*] Loading saved session from {}".format(SESSION_FILE))
        r = session.get("https://www.instagram.com/accounts/edit/", headers=session.headers, timeout=10)
        if r.status_code == 200 and ("Edit Profile" in r.text or "Profile" in r.text):
            logger.info("[+] Session seems valid (edit page accessible).")
            return True, None
        r2 = session.get("https://www.instagram.com/", headers=session.headers, timeout=10)
        if r2.status_code == 200 and "viewer" in r2.text:
            return True, None
        logger.info("[*] Saved session invalid or expired.")
    return False, None

def fetch_about_fragment(session: requests.Session, username: str):
    headers = dict(session.headers)
    for appid in ("1217981644879628", "936619743392459"):
        headers["X-IG-App-ID"] = appid
        try:
            r = session.get(WEB_PROFILE_API.format(username=username), headers=headers, timeout=12)
            if r.status_code == 200:
                try:
                    j = r.json()
                    if "data" in j and "user" in j["data"]:
                        u = j["data"]["user"]
                        return {"source": "web_profile_info_api", "payload": u}
                except Exception:
                    pass
        except Exception:
            pass

    for url in ABOUT_URLS:
        try:
            r = session.get(url.format(username=username), headers=session.headers, timeout=12)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        soup = BeautifulSoup(r.text, "lxml")
        txt = soup.get_text(" ", strip=True)
        info = {}
        m = re.search(r'\b(Date joined|Joined|Joined Instagram|Joined on)[:\s\-]*([A-Za-z0-9 ,]+)', txt, re.I)
        if m:
            info["date_joined"] = m.group(2).strip()
        m2 = re.search(r'\b(Country|Location|البلد|الموقع)[:\s\-]*([A-Za-z0-9 ,]+)', txt, re.I)
        if m2:
            info["country"] = m2.group(2).strip()
        h = soup.find(lambda t: t.name == "span" and t.get("role") == "heading")
        if h:
            info["username_fragment"] = h.get_text(" ", strip=True)
        img = soup.find("img")
        if img and img.get("src"):
            info["profile_image_fragment"] = img["src"]
        if info:
            return {"source": url.format(username=username), "payload": info}
    return {"source": "none", "payload": {}}

def Arthn_fake_payload() -> Dict[str, str]:
    return {
        "device_id": f"android-{''.join([str(random.randint(0, 9)) for _ in range(16)])}",
        "uuid": str(uuid.uuid4()),
        "app_version": "219.0.0.12.117",
        "timestamp": str(int(time.time())),
        "auth_token": base64.b64encode(os.urandom(32)).decode(),
        "X-Ig-Device-Id": str(uuid.uuid4()),
        "X-Ig-Android-Id": f"android-{''.join([str(random.randint(0, 9)) for _ in range(16)])}"
    }

def Arthn_init_db():
    conn = sqlite3.connect('darkstorm_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (username TEXT, sessionid TEXT, cookies TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sensitive_data
                 (username TEXT, data_type TEXT, data_value TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS targets
                 (username TEXT, followers INTEGER, timestamp TEXT)''')
    conn.commit()
    return conn

async def Arthn_store_session(username: str, sessionid: str, cookies: Dict) -> None:
    conn = Arthn_init_db()
    c = conn.cursor()
    c.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
              (username, sessionid, json.dumps(cookies), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

async def Arthn_store_sensitive_data(username: str, data_type: str, data_value: str) -> None:
    conn = Arthn_init_db()
    c = conn.cursor()
    c.execute("INSERT INTO sensitive_data VALUES (?, ?, ?, ?)",
              (username, data_type, data_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

async def Arthn_store_target(username: str, followers: int) -> None:
    conn = Arthn_init_db()
    c = conn.cursor()
    c.execute("INSERT INTO targets VALUES (?, ?, ?)",
              (username, followers, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

async def Arthn_exploit_session_hijack(username: str, sessionid: str) -> Dict[str, Any]:
    url = "https://i.instagram.com/api/v1/accounts/login/"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }
    payload = {
        "username": username,
        "device_id": headers["device_id"],
        "login_attempt_count": "0"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, headers=headers, json=payload) as res:
                if res.status == 200:
                    data = await res.json()
                    new_sessionid = data.get("logged_in_user", {}).get("sessionid", sessionid)
                    cookies = dict(res.cookies)
                    await Arthn_store_session(username, new_sessionid, cookies)
                    logger.info("[+] Session hijack attempt successful")
                    return {
                        "new_sessionid": new_sessionid,
                        "cookies": cookies,
                        "error": None
                    }
                else:
                    logger.error(f"[-] Session hijack failed: {await res.text()}")
                    return {"error": f"Session hijack failed: {await res.text()}"}
        except Exception as e:
            logger.error(f"[-] Error during session hijack: {str(e)}")
            return {"error": f"Session hijack error: {str(e)}"}

async def Arthn_extract_sensitive_data(username: str, sessionid: str) -> Dict[str, Any]:
    url = "https://i.instagram.com/api/v1/users/{}/info/".format(
        await Arthn_fetch_user_id(username, sessionid)
    )
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=10) as res:
                if res.status == 200:
                    data = await res.json()
                    user = data.get("user", {})
                    sensitive = {
                        "email": user.get("email", ""),
                        "phone_number": user.get("phone_number", ""),
                        "address": user.get("address_street", ""),
                        "city": user.get("city_name", ""),
                        "zip_code": user.get("zip_code", ""),
                        "cookies": dict(res.cookies)
                    }
                    for key, value in sensitive.items():
                        if value:
                            await Arthn_store_sensitive_data(username, key, str(value))
                    logger.info("[+] Extracted sensitive data")
                    return sensitive
                else:
                    logger.error(f"[-] Failed to extract sensitive data: {await res.text()}")
                    return {"error": f"Failed to extract sensitive data: {await res.text()}"}
        except Exception as e:
            logger.error(f"[-] Error extracting sensitive data: {str(e)}")
            return {"error": f"Error extracting sensitive data: {str(e)}"}

async def Arthn_validate_session(sessionid: str) -> Dict[str, Any]:
    url = "https://i.instagram.com/api/v1/accounts/current_user/"
    headers = {
        "User-Agent": "Instagram 219.0.0.12.117 Android",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=10) as res:
                if res.status == 200:
                    data = await res.json()
                    logger.info("[+] Session validated successfully")
                    return {
                        "username": data["user"]["username"],
                        "full_name": data["user"]["full_name"],
                        "is_private": data["user"]["is_private"],
                        "error": None,
                        "session_cookies": dict(res.cookies)
                    }
                else:
                    logger.error(f"[-] Session validation failed: {await res.text()}")
                    return {"error": f"Invalid session: {await res.text()}"}
    except Exception as e:
        logger.error(f"[-] Error validating session: {str(e)}")
        return {"error": f"Failed to validate session: {str(e)}"}

async def Arthn_retry_request(url: str, headers: Dict[str, str], session: aiohttp.ClientSession, retries: int = 7) -> Optional[Dict]:
    for attempt in range(retries):
        try:
            async with session.get(url, headers=headers, timeout=20) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        cookies = dict(response.cookies)
                        if cookies:
                            logger.info("[+] Extracted cookies from response")
                            data["extracted_cookies"] = cookies
                        return data
                    except aiohttp.ContentTypeError:
                        logger.error(f"[-] Invalid JSON response from {url}")
                        return {"error": "Invalid JSON response"}
                elif response.status == 429:
                    logger.warning(f"[-] Rate limit hit, retrying after {2 ** attempt} seconds...")
                    await asyncio.sleep(2 ** attempt)
                elif response.status == 403:
                    logger.error(f"[-] Forbidden: Possible private account or session issue")
                    return {"error": "Forbidden: Check session ID or account privacy"}
                else:
                    logger.error(f"[-] Failed request to {url}: {response.status}")
                    return {"error": f"Error {response.status}: {await response.text()}"}
        except Exception as e:
            logger.error(f"[-] Error in request to {url}: {str(e)}")
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
    return {"error": "Max retries exceeded"}

async def Arthn_fetch_instagram_data(username: str, sessionid: str, max_pages: int = 10) -> Dict[str, Any]:
    global hashtag_fetch_count
    url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error("[-] Failed to fetch profile data")
            graphql_url = f"https://www.instagram.com/api/graphql"
            payload = {
                "query_hash": "c9100bf9110dd6361671f113dd02e7d6",
                "variables": json.dumps({"username": username})
            }
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                async with session.post(graphql_url, headers=headers, data=payload) as res:
                    if res.status == 200:
                        data = await res.json()
                        user = data.get("data", {}).get("user", {})
                        if user:
                            logger.info("[+] Fallback GraphQL fetch successful")
                        else:
                            return {"username": username, "error": "User not found via GraphQL", "hashtags": [], "tagged_users": []}
                    else:
                        return {"username": username, "error": f"GraphQL fallback failed: {await res.text()}", "hashtags": [], "tagged_users": []}
            except Exception as e:
                return {"username": username, "error": f"GraphQL fallback error: {str(e)}", "hashtags": [], "tagged_users": []}
        else:
            user = data.get("data", {}).get("user", {})

        if not user:
            logger.error("[-] User not found")
            return {"username": username, "error": "User not found", "hashtags": [], "tagged_users": []}

        logger.info(f"[+] Successfully fetched profile data for {username}")
        result = {
            "queried": username,
            "source": "web_profile_info_api",
            "ai_agent_type": user.get("ai_agent_type", None),
            "biography": user.get("biography", None),
            "bio_links": user.get("bio_links", []),
            "blocked_by_viewer": user.get("blocked_by_viewer", False),
            "restricted_by_viewer": user.get("restricted_by_viewer", False),
            "country_block": user.get("country_block", False),
            "edge_followed_by": {"count": user.get("edge_followed_by", {}).get("count", 0)},
            "edge_follow": {"count": user.get("edge_follow", {}).get("count", 0)},
            "group_metadata": user.get("group_metadata", None),
            "has_ar_effects": user.get("has_ar_effects", False),
            "has_clips": user.get("has_clips", False),
            "has_guides": user.get("has_guides", False),
            "has_chaining": user.get("has_chaining", False),
            "has_channel": user.get("has_channel", False),
            "has_blocked_viewer": user.get("has_blocked_viewer", False),
            "highlight_reel_count": user.get("highlight_reel_count", 0),
            "is_business_account": user.get("is_business_account", False),
            "is_professional_account": user.get("is_professional_account", False),
            "is_private": user.get("is_private", False),
            "is_verified": user.get("is_verified", False),
            "is_supervision_enabled": user.get("is_supervision_enabled", False),
            "is_embeds_disabled": user.get("is_embeds_disabled", False),
            "is_joined_recently": user.get("is_joined_recently", False),
            "pinned_channels_list_count": user.get("pinned_channels_list_count", 0),
            "profile_picture_present": bool(user.get("profile_pic_url", "")),
            "requested_by_viewer": user.get("requested_by_viewer", False),
            "should_show_category": user.get("should_show_category", False),
            "should_show_public_contacts": user.get("should_show_public_contacts", False),
            "show_account_transparency_details": user.get("show_account_transparency_details", False),
            "transparency_label": user.get("transparency_label", None),
            "transparency_product": user.get("transparency_product", None),
            "pronouns": user.get("pronouns", [""]),
            "edge_owner_to_timeline_media": {
                "count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                "page_info": {
                    "has_next_page": user.get("edge_owner_to_timeline_media", {}).get("page_info", {}).get("has_next_page", False),
                    "end_cursor": user.get("edge_owner_to_timeline_media", {}).get("page_info", {}).get("end_cursor", "")
                },
                "edges": user.get("edge_owner_to_timeline_media", {}).get("edges", [])
            },
            "username": user.get("username", ""),
            "full_name": user.get("full_name", ""),
            "user_id": user.get("id", ""),
            "bio": user.get("biography", ""),
            "followers_count": user.get("edge_followed_by", {}).get("count", 0),
            "following_count": user.get("edge_follow", {}).get("count", 0),
            "post_count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
            "profile_pic_url": user.get("profile_pic_url", ""),
            "external_url": user.get("external_url", ""),
            "category": user.get("category_name", ""),
            "business_email": user.get("business_email", ""),
            "business_phone": user.get("business_phone_number", ""),
            "business_category": user.get("business_category_name", ""),
            "pinned_posts": [],
            "posts": [],
            "hashtags": [],
            "tagged_users": [],
            "sensitive_data": data.get("extracted_cookies", {}),
            "hijacked_session": {},
            "additional_sensitive_data": {}
        }

        session_hijack = await Arthn_exploit_session_hijack(username, sessionid)
        result["hijacked_session"] = session_hijack
        sensitive_data = await Arthn_extract_sensitive_data(username, sessionid)
        result["additional_sensitive_data"] = sensitive_data

        if result["is_private"] and not sessionid:
            logger.info("[-] Private account, skipping posts")
            return result

        posts = user.get("edge_owner_to_timeline_media", {}).get("edges", [])
        next_max_id = user.get("edge_owner_to_timeline_media", {}).get("page_info", {}).get("end_cursor")
        locations = []
        captions = []
        mentions = []
        hashtags = []
        tagged_users = []
        post_count = 0
        page_count = 0

        for post in posts:
            if post_count >= 300:
                logger.info("[+] Reached 300 posts limit")
                break
            node = post.get("node", {})
            location = node.get("location", {})
            if location and location.get("name"):
                locations.append({
                    "location_name": location.get("name"),
                    "latitude": location.get("lat"),
                    "longitude": location.get("lng"),
                    "post_timestamp": node.get("taken_at_timestamp")
                })

            caption = node.get("edge_media_to_caption", {}).get("edges", [])
            text = caption[0].get("node", {}).get("text", "") if caption else ""
            captions.append(text)
            post_mentions = re.findall(r"@([\w.]+)", text)
            post_hashtags = re.findall(r"#([\w]+)", text)
            post_tagged = [user["node"]["username"] for user in node.get("edge_media_to_tagged_user", {}).get("edges", [])]

            media_type = "Video" if node.get("is_video") else "Image"
            if node.get("edge_sidecar_to_children"):
                media_type = "Carousel"

            post_data = {
                "post_id": node.get("id", ""),
                "shortcode": node.get("shortcode", ""),
                "timestamp": node.get("taken_at_timestamp", 0),
                "likes": node.get("edge_liked_by", {}).get("count", 0),
                "comments_count": node.get("edge_media_to_comment", {}).get("count", 0),
                "media_type": media_type,
                "caption": text,
                "url": f"https://www.instagram.com/p/{node.get('shortcode', '')}/",
                "mentions": post_mentions,
                "hashtags": post_hashtags,
                "tagged_users": post_tagged,
                "is_pinned": node.get("is_pinned", False),
                "is_sponsored": node.get("is_ad", False)
            }
            result["posts"].append(post_data)
            if node.get("is_pinned", False):
                result["pinned_posts"].append(node.get("shortcode", ""))

            mentions.extend(post_mentions)
            hashtags.extend(post_hashtags)
            tagged_users.extend(post_tagged)
            post_count += 1

        while next_max_id and post_count < 300 and page_count < max_pages:
            posts_url = f"https://i.instagram.com/api/v1/feed/user/{username}/?count=12&max_id={next_max_id}"
            post_data = await Arthn_retry_request(posts_url, headers, session)
            if "error" in post_data:
                logger.error("[-] Failed to fetch additional posts")
                break
            posts = post_data.get("items", [])
            next_max_id = post_data.get("next_max_id")
            page_count += 1
            if not posts:
                logger.info("[+] No more posts to fetch")
                break
            for post in posts:
                if post_count >= 300:
                    logger.info("[+] Reached 300 posts limit")
                    break
                node = post
                location = node.get("location", {})
                if location and location.get("name"):
                    locations.append({
                        "location_name": location.get("name"),
                        "latitude": node.get("lat"),
                        "longitude": node.get("lng"),
                        "post_timestamp": node.get("taken_at")
                    })

                caption = node.get("caption", {}).get("text", "") if node.get("caption") else ""
                captions.append(caption)
                post_mentions = re.findall(r"@([\w.]+)", caption)
                post_hashtags = re.findall(r"#([\w]+)", caption)
                post_tagged = [user["user"]["username"] for user in node.get("usertags", {}).get("in", [])]

                media_type = "Video" if node.get("media_type") == 2 else "Image"
                if node.get("carousel_media"):
                    media_type = "Carousel"

                post_data = {
                    "post_id": node.get("id", ""),
                    "shortcode": node.get("code", ""),
                    "timestamp": node.get("taken_at", 0),
                    "likes": node.get("like_count", 0),
                    "comments_count": node.get("comment_count", 0),
                    "media_type": media_type,
                    "caption": caption,
                    "url": f"https://www.instagram.com/p/{node.get('code', '')}/",
                    "mentions": post_mentions,
                    "hashtags": post_hashtags,
                    "tagged_users": post_tagged,
                    "is_pinned": node.get("is_pinned", False),
                    "is_sponsored": node.get("is_ad", False)
                }
                result["posts"].append(post_data)
                if node.get("is_pinned", False):
                    result["pinned_posts"].append(node.get("code", ""))

                mentions.extend(post_mentions)
                hashtags.extend(post_hashtags)
                tagged_users.extend(post_tagged)
                post_count += 1

            await asyncio.sleep(0.5)

        result["locations"] = locations
        result["mentions"] = list(set(mentions))
        result["hashtags"] = list(set(hashtags)) if hashtags else ["None found"]
        result["tagged_users"] = list(set(tagged_users)) if tagged_users else ["None found"]
        result["captions"] = captions
        hashtag_fetch_count += 1
        logger.info(f"[+] Fetched {len(result['posts'])} posts, Hashtag Fetch #{hashtag_fetch_count}")
        return result

async def Arthn_fetch_comments(shortcode: str, sessionid: str, max_id: Optional[str] = None) -> List[Dict[str, Any]]:
    url = f"https://i.instagram.com/api/v1/media/{shortcode}/comments/"
    if max_id:
        url += f"?max_id={max_id}"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        comments = []
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch comments for {shortcode}: {data['error']}")
            return comments
        for comment in data.get("comments", [])[:20]:
            comments.append({
                "username": comment.get("user", {}).get("username", ""),
                "text": comment.get("text", ""),
                "timestamp": comment.get("created_at", 0)
            })
        logger.info(f"[+] Fetched {len(comments)} comments for post {shortcode}")
        return comments

async def Arthn_fetch_followers(user_id: str, sessionid: str, max_followers: int) -> List[str]:
    url = f"https://i.instagram.com/api/v1/friendships/{user_id}/followers/"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    followers = []
    async with aiohttp.ClientSession() as session:
        next_max_id = None
        page_count = 0
        while len(followers) < max_followers and page_count < 10:
            fetch_url = url if not next_max_id else f"{url}?max_id={next_max_id}"
            data = await Arthn_retry_request(fetch_url, headers, session)
            if "error" in data:
                logger.error(f"[-] Failed to fetch followers: {data['error']}")
                break
            users = data.get("users", [])
            followers.extend(user["username"] for user in users)
            next_max_id = data.get("next_max_id")
            page_count += 1
            if not next_max_id or not users:
                logger.info("[+] No more followers to fetch")
                break
            await asyncio.sleep(0.5)
        logger.info(f"[+] Fetched {len(followers)} followers")
        return followers[:max_followers]

async def Arthn_check_follower_relationships(followers: List[str], target_data: Dict[str, Any], sessionid: str, num_to_display: int) -> List[Dict[str, Any]]:
    relationships = []
    mentions = target_data.get("mentions", [])
    tagged_users = target_data.get("tagged_users", [])
    comments = target_data.get("posts_comments", [])
    commenters = [c["username"] for p in comments for c in p if isinstance(p, list)]
    mutual_connections = target_data.get("mutual_connections", {}).get("mutual", [])
    captions = target_data.get("captions", [])

    async def fetch_follower_data(follower: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={follower}"
        headers = {
            "User-Agent": Arthn_ua.random,
            "X-IG-App-ID": "936619743392459",
            "Accept": "application/json",
            "Cookie": f"sessionid={sessionid};",
            **Arthn_fake_payload()
        }
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch data for {follower}: {data['error']}")
            return {"username": follower, "error": data["error"]}
        user = data.get("data", {}).get("user", {})
        return {
            "username": user.get("username", ""),
            "full_name": user.get("full_name", ""),
            "followers_count": user.get("edge_followed_by", {}).get("count", 0)
        }

    async def check_one(follower: str, session: aiohttp.ClientSession):
        follower_data = await fetch_follower_data(follower, session)
        relationship = []
        details = []
        engagement_score = 0

        if follower in mutual_connections:
            relationship.append("Mutual Follower")
            details.append("Follows each other")
            engagement_score += 2
        else:
            relationship.append("Follower")
            details.append(f"{follower} follows target")

        mention_count = sum(1 for m in mentions if m == follower)
        if mention_count > 0:
            relationship.append("Mentioned")
            details.append(f"Mentioned {mention_count} times")
            engagement_score += mention_count

        tag_count = sum(1 for t in tagged_users if t == follower)
        if tag_count > 0:
            relationship.append("Tagged")
            details.append(f"Tagged {tag_count} times")
            engagement_score += tag_count * 2

        comment_count = sum(1 for c in commenters if c == follower)
        if comment_count > 0:
            relationship.append("Commenter")
            details.append(f"Commented {comment_count} times")
            engagement_score += comment_count

        interaction_texts = [c for c in captions if f"@{follower}" in c.lower()] + \
                           [c["text"] for p in comments for c in p if c["username"] == follower]
        positive_keywords = ["great", "awesome", "love", "amazing", "😊", "❤️"]
        negative_keywords = ["sad", "bad", "hate", "terrible", "😢", "😡"]
        positive_score = sum(1 for t in interaction_texts for w in positive_keywords if w.lower() in t.lower())
        negative_score = sum(1 for t in interaction_texts for w in negative_keywords if w.lower() in t.lower())
        sentiment = "Neutral"
        if positive_score > negative_score:
            sentiment = "Positive"
            engagement_score += positive_score * 0.5
        elif negative_score > positive_score:
            sentiment = "Negative"
            engagement_score -= negative_score * 0.5

        relationship = ", ".join(relationship) if relationship else "Follower"
        details = "; ".join(details) if details else "Follows target"
        return {
            "username": follower,
            "relationship": relationship,
            "details": details,
            "engagement_score": min(engagement_score, 10),
            "sentiment": sentiment,
            "follower_data": follower_data
        }

    async with aiohttp.ClientSession() as session:
        tasks = [check_one(follower, session) for follower in followers[:num_to_display]]
        relationships = await asyncio.gather(*tasks, return_exceptions=True)
        relationships = [r for r in relationships if isinstance(r, dict)]
        logger.info(f"[+] Checked relationships for {len(relationships)} followers")
        return relationships

async def Arthn_fetch_user_id(username: str, sessionid: str) -> str:
    url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch user ID: {data['error']}")
            return ""
        user = data.get("data", {}).get("user", {})
        logger.info("[+] Fetched user ID")
        return user.get("id", "")

async def Arthn_fetch_mutual_connections(user_id: str, sessionid: str) -> Dict[str, Any]:
    url_followers = f"https://i.instagram.com/api/v1/friendships/{user_id}/followers/"
    url_following = f"https://i.instagram.com/api/v1/friendships/{user_id}/following/"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        followers_data, following_data = await asyncio.gather(
            Arthn_retry_request(url_followers, headers, session),
            Arthn_retry_request(url_following, headers, session)
        )
        if "error" in followers_data or "error" in following_data:
            logger.error(f"[-] Failed to fetch mutual connections: {followers_data.get('error', following_data.get('error', 'Unknown error'))}")
            return {"followers": [], "following": [], "mutual": []}

        followers = [user["username"] for user in followers_data.get("users", [])]
        following = [user["username"] for user in following_data.get("users", [])]
        mutual = list(set(followers) & set(following))
        logger.info(f"[+] Found {len(mutual)} mutual connections")
        return {"followers": followers, "following": following, "mutual": mutual}

async def Arthn_fetch_stories(user_id: str, sessionid: str, max_pages: int = 5) -> List[Dict[str, Any]]:
    url = f"https://i.instagram.com/api/v1/feed/reels_media/?user_ids={user_id}"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        stories = []
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch stories: {data['error']}")
            public_url = f"https://www.instagram.com/stories/{user_id}/"
            try:
                async with session.get(public_url, headers={"User-Agent": Arthn_ua.random}) as res:
                    if res.status == 200:
                        soup = BeautifulSoup(await res.text(), "html.parser")
                        scripts = soup.find_all("script")
                        for script in scripts:
                            if "window.__additionalDataLoaded" in script.text:
                                json_data = re.search(r'\{.*\}', script.text)
                                if json_data:
                                    stories_data = json.loads(json_data.group(0)).get("reel", {}).get("items", [])
                                    for item in stories_data[:10]:
                                        url = item.get("video_versions", [{}])[0].get("url", item.get("image_versions2", {}).get("candidates", [{}])[0].get("url", "None"))
                                        stories.append({
                                            "id": item.get("id", "Unknown"),
                                            "timestamp": item.get("taken_at", 0),
                                            "url": url
                                        })
                                    logger.info("[+] Fallback public stories fetch successful")
                                    return stories
            except Exception as e:
                logger.error(f"[-] Public stories fallback failed: {str(e)}")
            return [{"id": "None", "timestamp": 0, "url": "None", "error": data["error"]}]

        reels = data.get("reels", {})
        user_reels = reels.get(user_id, {}).get("items", [])[:20]
        if not user_reels:
            logger.info("[+] No stories found")
            return [{"id": "None", "timestamp": 0, "url": "None", "error": "No stories available"}]
        for item in user_reels:
            url = item.get("video_versions", [{}])[0].get("url", item.get("image_versions2", {}).get("candidates", [{}])[0].get("url", "None"))
            stories.append({
                "id": item.get("id", "Unknown"),
                "timestamp": item.get("taken_at", 0),
                "url": url
            })
        logger.info(f"[+] Fetched {len(stories)} stories")
        return stories

async def Arthn_fetch_highlights(user_id: str, sessionid: str, max_pages: int = 5) -> List[Dict[str, Any]]:
    url = f"https://i.instagram.com/api/v1/highlights/{user_id}/highlights_tray/"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }

    async with aiohttp.ClientSession() as session:
        highlights = []
        data = await Arthn_retry_request(url, headers, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch highlights: {data['error']}")
            public_url = f"https://www.instagram.com/{user_id}/"
            try:
                async with session.get(public_url, headers={"User-Agent": Arthn_ua.random}) as res:
                    if res.status == 200:
                        soup = BeautifulSoup(await res.text(), "html.parser")
                        scripts = soup.find_all("script")
                        for script in scripts:
                            if "window.__additionalDataLoaded" in script.text:
                                json_data = re.search(r'\{.*\}', script.text)
                                if json_data:
                                    highlights_data = json.loads(json_data.group(0)).get("user", {}).get("edge_highlight_reels", {}).get("edges", [])
                                    for item in highlights_data[:10]:
                                        node = item.get("node", {})
                                        url = node.get("cover_media", {}).get("thumbnail_src", "None")
                                        highlights.append({
                                            "id": node.get("id", "Unknown"),
                                            "title": node.get("title", "Untitled"),
                                            "timestamp": node.get("taken_at_timestamp", 0),
                                            "url": url
                                        })
                                    logger.info("[+] Fallback public highlights fetch successful")
                                    return highlights
            except Exception as e:
                logger.error(f"[-] Public highlights fallback failed: {str(e)}")
            return [{"id": "None", "title": "None", "timestamp": 0, "url": "None", "error": data["error"]}]

        trays = data.get("tray", [])[:20]
        if not trays:
            logger.info("[+] No highlights found")
            return [{"id": "None", "title": "None", "timestamp": 0, "url": "None", "error": "No highlights available"}]

        for tray in trays:
            for item in tray.get("items", [])[:10]:
                url = item.get("video_versions", [{}])[0].get("url", item.get("image_versions2", {}).get("candidates", [{}])[0].get("url", "None"))
                highlights.append({
                    "id": item.get("id", "Unknown"),
                    "title": item.get("title", "Untitled"),
                    "timestamp": item.get("taken_at", 0),
                    "url": url
                })
        logger.info(f"[+] Fetched {len(highlights)} highlights")
        return highlights

def Arthn_classify_relationships(mentions: List[str], tagged_users: List[str], captions: List[str], mutual_connections: List[str]) -> Dict[str, Any]:
    relationship_indicators = {
        "romantic": ["love", "partner", "honey", "darling", "💕", "❤️"],
        "friend": ["friend", "bestie", "bff"],
        "family": ["mom", "dad", "sister", "brother"],
        "professional": ["colleague", "work", "team"]
    }

    captions_text = " ".join(captions).lower()
    mention_freq = Counter(mentions + tagged_users)
    relationships = {}

    for mention in mention_freq:
        classification = "Mentioned"
        score = mention_freq[mention]
        is_mutual = mention in mutual_connections
        for category, indicators in relationship_indicators.items():
            if any(indicator in captions_text for indicator in indicators) and score > 1:
                classification = category.capitalize()
                break
        if is_mutual:
            score *= 1.5
        relationships[mention] = {
            "username": mention,
            "mention_count": mention_freq[mention],
            "classification": classification,
            "is_mutual": is_mutual,
            "confidence_score": min(score / 10, 1.0)
        }

    logger.info(f"[+] Classified {len(relationships)} relationships")
    return relationships

def Arthn_estimate_location(locations: List[Dict]) -> Dict[str, str]:
    if not locations:
        logger.info("[+] No locations found")
        return {"country": "Unknown", "region": "Unknown"}
    geolocator = Nominatim(user_agent="ArthnOSINT")
    most_common = Counter(loc["location_name"] for loc in locations).most_common(1)
    if not most_common:
        return {"country": "Unknown", "region": "Unknown"}
    location_name = most_common[0][0]
    try:
        location = geolocator.geocode(location_name, timeout=5)
        if location:
            parts = location.address.split(", ")
            country = parts[-1] if len(parts) > 1 else "Unknown"
            region = parts[-2] if len(parts) > 2 else "Unknown"
            logger.info("[+] Estimated location")
            return {"country": country, "region": region}
        return {"country": "Unknown", "region": "Unknown"}
    except:
        logger.error("[-] Failed to geocode location")
        return {"country": "Unknown", "region": "Unknown"}

async def Arthn_scrape_external_links(external_url: str) -> Dict[str, Any]:
    if not external_url:
        logger.info("[+] No external link provided")
        return {"external_data": "No external link"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(external_url, headers={"User-Agent": Arthn_ua.random}, timeout=5) as response:
                if response.status == 200:
                    soup = BeautifulSoup(await response.text(), "html.parser")
                    title = soup.find("title")
                    social_links = [a["href"] for a in soup.find_all("a", href=True) if any(x in a["href"] for x in ["twitter.com", "facebook.com", "linkedin.com", "tiktok.com", "youtube.com", "x.com"])]
                    emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", await response.text())
                    phone_numbers = re.findall(r"\b\+?\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", await response.text())
                    logger.info(f"[+] Scraped external link {external_url}")
                    return {
                        "external_url": external_url,
                        "page_title": title.text if title else "No title",
                        "emails": emails,
                        "phone_numbers": phone_numbers,
                        "social_links": social_links
                    }
                return {"external_data": f"Failed to fetch link: {response.status}"}
    except Exception as e:
        logger.error(f"[-] Error scraping external link: {str(e)}")
        return {"external_data": f"Error fetching link: {str(e)}"}

async def Arthn_fetch_username_history(username: str) -> List[Dict[str, str]]:
    url = f"https://web.archive.org/cdx/search/cdx?url=instagram.com/{username}&output=json"
    async with aiohttp.ClientSession() as session:
        data = await Arthn_retry_request(url, {"User-Agent": Arthn_ua.random}, session)
        if "error" in data:
            logger.error(f"[-] Failed to fetch username history: {data['error']}")
            return []
        snapshots = [{"timestamp": entry[1], "url": f"https://web.archive.org/web/{entry[1]}/https://instagram.com/{username}"} for entry in data[1:]][:10]
        logger.info(f"[+] Fetched {len(snapshots)} username history snapshots")
        return snapshots

def Arthn_analyze_hashtag_interests(hashtags: List[str]) -> Dict[str, Any]:
    hashtag_categories = {
        "travel": ["travel", "adventure", "explore", "vacation"],
        "food": ["food", "cooking", "recipe"],
        "fitness": ["fitness", "gym", "workout"],
        "fashion": ["fashion", "style", "outfit"],
        "lifestyle": ["lifestyle", "life", "vibes"]
    }
    interests = defaultdict(list)
    hashtag_freq = Counter(hashtags)
    for hashtag in hashtag_freq:
        for category, tags in hashtag_categories.items():
            if hashtag.lower() in [t.lower() for t in tags]:
                interests[category].append({"hashtag": hashtag, "count": hashtag_freq[hashtag]})
    logger.info(f"[+] Analyzed {len(interests)} interests")
    return dict(interests)

def Arthn_analyze_hashtag_cooccurrence(hashtags: List[str], posts: List[Dict]) -> Dict[str, Any]:
    pairs = []
    for post in posts:
        post_hashtags = post.get("hashtags", [])
        for i, h1 in enumerate(post_hashtags):
            for h2 in post_hashtags[i+1:]:
                pairs.append(tuple(sorted([h1.lower(), h2.lower()])))
    pair_freq = Counter(pairs).most_common(10)
    logger.info("[+] Analyzed hashtag co-occurrence")
    return {f"{h1}#{h2}": count for (h1, h2), count in pair_freq}

def Arthn_analyze_content_types(posts: List[Dict]) -> Dict[str, float]:
    types = Counter(post["media_type"] for post in posts)
    total = sum(types.values())
    logger.info("[+] Analyzed content types")
    return {k: v / total if total else 0 for k, v in types.items()}

def Arthn_analyze_sentiment(captions: List[str], comments: List[List[Dict]]) -> Dict[str, Any]:
    positive_keywords = ["great", "awesome", "love", "amazing", "😊", "❤️"]
    negative_keywords = ["sad", "bad", "hate", "terrible", "😢", "😡"]

    caption_positive = sum(1 for c in captions for w in positive_keywords if w.lower() in c.lower())
    caption_negative = sum(1 for c in captions for w in negative_keywords if w.lower() in c.lower())
    caption_total = caption_positive + caption_negative

    comment_positive = sum(1 for p in comments for c in p for w in positive_keywords if w.lower() in c["text"].lower())
    comment_negative = sum(1 for p in comments for c in p for w in negative_keywords if w.lower() in c["text"].lower())
    comment_total = comment_positive + comment_negative

    logger.info("[+] Analyzed sentiment")
    return {
        "caption_sentiment": {
            "positive_ratio": caption_positive / caption_total if caption_total else 0,
            "negative_ratio": caption_negative / caption_total if caption_total else 0
        },
        "comment_sentiment": {
            "positive_ratio": comment_positive / comment_total if comment_total else 0,
            "negative_ratio": comment_negative / comment_total if comment_total else 0
        }
    }

def Arthn_analyze_location_timeline(locations: List[Dict]) -> List[Dict[str, Any]]:
    if not locations:
        logger.info("[+] No location timeline data")
        return []
    timeline = sorted(
        [{"location": loc["location_name"], "timestamp": datetime.fromtimestamp(loc["post_timestamp"]).strftime("%Y-%m-%d")}
         for loc in locations if loc.get("post_timestamp")],
        key=lambda x: x["timestamp"]
    )[:10]
    logger.info("[+] Analyzed location timeline")
    return timeline

def Arthn_analyze_commenters(comments: List[List[Dict]]) -> Dict[str, Any]:
    commenter_freq = Counter(c["username"] for p in comments for c in p if isinstance(p, list)).most_common(10)
    logger.info("[+] Analyzed commenters")
    return {username: {"comment_count": count} for username, count in commenter_freq}

def Arthn_analyze_bio(bio: str) -> Dict[str, Any]:
    emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", bio)
    social_handles = re.findall(r"(?:twitter|x|tiktok|youtube|linkedin)\.com/[\w]+", bio)
    phone_numbers = re.findall(r"\b\+?\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", bio)
    logger.info("[+] Analyzed bio")
    return {"emails": emails, "social_handles": social_handles, "phone_numbers": phone_numbers}

async def Arthn_estimate_account_age(username: str, sessionid: str, posts: List[Dict] = None) -> str:
    try:
        session = load_session(SESSION_FILE)
        logged, _ = ensure_logged_in(session)
        if logged:
            about_data = fetch_about_fragment(session, username)
            if about_data["source"] != "none" and "date_joined" in about_data["payload"]:
                logger.info("[+] Account age retrieved from About This Account")
                return about_data["payload"]["date_joined"]

        if posts and posts:
            oldest_post = min(posts, key=lambda p: p.get("timestamp", float('inf')))
            oldest_timestamp = oldest_post.get("timestamp", 0)
            if oldest_timestamp > 0:
                creation_date = datetime.fromtimestamp(oldest_timestamp).strftime("%Y-%m-%d")
                logger.info("[+] Estimated account age based on oldest post")
                return creation_date

        base_timestamp = 1286352000
        estimated_ids_per_day = 100000000
        user_id = await Arthn_fetch_user_id(username, sessionid)
        if not user_id:
            logger.error("[-] Failed to fetch user ID for age estimation")
            return "Unknown"
        user_id_int = int(user_id)
        days_since_start = user_id_int / estimated_ids_per_day
        estimated_creation = base_timestamp + (days_since_start * 86400)
        creation_date = datetime.fromtimestamp(estimated_creation).strftime("%Y-%m-%d")
        logger.info("[+] Estimated account age based on linear approximation")
        return creation_date
    except Exception as e:
        logger.error(f"[-] Failed to estimate account age: {str(e)}")
        return "Unknown"

async def Arthn_logout(sessionid: str) -> bool:
    url = "https://i.instagram.com/api/v1/accounts/logout/"
    headers = {
        "User-Agent": Arthn_ua.random,
        "X-IG-App-ID": "936619743392459",
        "Accept": "application/json",
        "Cookie": f"sessionid={sessionid};",
        **Arthn_fake_payload()
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers) as res:
                if res.status == 200:
                    logger.info("[+] Successfully logged out")
                    return True
                else:
                    logger.error(f"[-] Logout failed: {await res.text()}")
                    return False
    except Exception as e:
        logger.error(f"[-] Logout error: {str(e)}")
        return False

async def Arthn_get_full_user_info(username: str, sessionid: str, input_followers: int) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    target_data = await Arthn_fetch_instagram_data(username, sessionid)
    if "error" in target_data:
        return target_data, []

    user_id = target_data.get("user_id", "")
    if user_id:
        comments = []
        for post in target_data["posts"][:5]:
            comments.append(await Arthn_fetch_comments(post["shortcode"], sessionid))
        target_data["posts_comments"] = comments
        followers = await Arthn_fetch_followers(user_id, sessionid, max_followers=input_followers)
        target_data["followers"] = followers
        mutual_connections = await Arthn_fetch_mutual_connections(user_id, sessionid)
        target_data["mutual_connections"] = mutual_connections
        target_data["stories"] = await Arthn_fetch_stories(user_id, sessionid)
        target_data["highlights"] = await Arthn_fetch_highlights(user_id, sessionid)
        target_data["relationships"] = Arthn_classify_relationships(
            target_data.get("mentions", []),
            target_data.get("tagged_users", []),
            target_data.get("captions", []),
            mutual_connections.get("mutual", [])
        )
        target_data["estimated_location"] = Arthn_estimate_location(target_data.get("locations", []))
        target_data["external_data"] = await Arthn_scrape_external_links(target_data.get("external_url", ""))
        target_data["username_history"] = await Arthn_fetch_username_history(username)
        target_data["hashtag_interests"] = Arthn_analyze_hashtag_interests(target_data.get("hashtags", []))
        target_data["hashtag_cooccurrence"] = Arthn_analyze_hashtag_cooccurrence(target_data.get("hashtags", []), target_data.get("posts", []))
        target_data["content_types"] = Arthn_analyze_content_types(target_data.get("posts", []))
        target_data["sentiment_analysis"] = Arthn_analyze_sentiment(target_data.get("captions", []), target_data.get("posts_comments", []))
        target_data["location_timeline"] = Arthn_analyze_location_timeline(target_data.get("locations", []))
        target_data["commenters"] = Arthn_analyze_commenters(target_data.get("posts_comments", []))
        target_data["bio_analysis"] = Arthn_analyze_bio(target_data.get("bio", ""))
        target_data["account_age"] = await Arthn_estimate_account_age(username, sessionid, target_data.get("posts", []))
        follower_relationships = await Arthn_check_follower_relationships(followers, target_data, sessionid, num_to_display=input_followers)
    else:
        follower_relationships = []

    return target_data, follower_relationships
