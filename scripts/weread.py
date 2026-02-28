import argparse
import hashlib
import logging
import os
import re
import time
from datetime import datetime
from http.cookies import SimpleCookie

import requests
from dotenv import load_dotenv
from notion_client import Client
from requests.utils import cookiejar_from_dict
from retrying import retry

from utils import (
    get_callout,
    get_date,
    get_heading,
    get_icon,
    get_number,
    get_quote,
    get_table_of_contents,
    get_title,
)

load_dotenv()

WEREAD_URL = "https://weread.qq.com/"
WEREAD_NOTEBOOKS_URL = "https://weread.qq.com/api/user/notebook"
WEREAD_BOOKMARKLIST_URL = "https://weread.qq.com/web/book/bookmarklist"
WEREAD_CHAPTER_INFO = "https://weread.qq.com/web/book/chapterInfos"
WEREAD_READ_INFO_URL = "https://weread.qq.com/web/book/readinfo"
WEREAD_REVIEW_LIST_URL = "https://weread.qq.com/web/review/list"
WEREAD_BOOK_INFO = "https://weread.qq.com/web/book/info"


# -----------------------------
# Helpers
# -----------------------------
def parse_cookie_string(cookie_string: str):
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    cookies_dict = {}
    cookiejar = None
    for key, morsel in cookie.items():
        cookies_dict[key] = morsel.value
        cookiejar = cookiejar_from_dict(cookies_dict, cookiejar=None, overwrite=True)
    return cookiejar


def refresh_token(_exception):
    # Touch homepage to refresh session; retrying lib expects a boolean return via retry_on_exception,
    # but this project uses it as "call then retry". We'll keep compatible behavior.
    session.get(WEREAD_URL)
    return True


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_bookmark_list(bookId):
    """获取我的划线"""
    session.get(WEREAD_URL)
    params = dict(bookId=bookId)
    r = session.get(WEREAD_BOOKMARKLIST_URL, params=params)
    if r.ok:
        updated = r.json().get("updated", [])
        updated = sorted(
            updated,
            key=lambda x: (x.get("chapterUid", 1), int(x.get("range").split("-")[0])),
        )
        return updated
    return []


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_read_info(bookId):
    session.get(WEREAD_URL)
    params = dict(bookId=bookId, readingDetail=1, readingBookIndex=1, finishedDate=1)
    r = session.get(WEREAD_READ_INFO_URL, params=params)
    if r.ok:
        return r.json()
    return None


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_bookinfo(bookId):
    """获取书的详情"""
    session.get(WEREAD_URL)
    params = dict(bookId=bookId)
    r = session.get(WEREAD_BOOK_INFO, params=params)
    if r.ok:
        data = r.json()
        isbn = data.get("isbn", "")
        newRating = data.get("newRating", 0) / 1000
        return (isbn, newRating)
    return ("", 0)


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_review_list(bookId):
    """获取笔记"""
    session.get(WEREAD_URL)
    params = dict(bookId=bookId, listType=11, mine=1, syncKey=0)
    r = session.get(WEREAD_REVIEW_LIST_URL, params=params)
    if not r.ok:
        return [], []
    reviews = r.json().get("reviews", []) or []
    summary = list(filter(lambda x: x.get("review", {}).get("type") == 4, reviews))
    notes = list(filter(lambda x: x.get("review", {}).get("type") == 1, reviews))
    notes = list(map(lambda x: x.get("review"), notes))
    notes = list(map(lambda x: {**x, "markText": x.pop("content")}, notes))
    return summary, notes


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_chapter_info(bookId):
    """获取章节信息"""
    session.get(WEREAD_URL)
    body = {"bookIds": [bookId], "synckeys": [0], "teenmode": 0}
    r = session.post(WEREAD_CHAPTER_INFO, json=body)
    if (
        r.ok
        and "data" in r.json()
        and len(r.json()["data"]) == 1
        and "updated" in r.json()["data"][0]
    ):
        update = r.json()["data"][0]["updated"]
        return {item["chapterUid"]: item for item in update}
    return None


def get_notebooklist():
    """获取笔记本列表"""
    session.get(WEREAD_URL)
    r = session.get(WEREAD_NOTEBOOKS_URL)
    if r.ok:
        data = r.json()
        books = data.get("books", []) or []
        books.sort(key=lambda x: x.get("sort", 0))
        return books
    print(r.text)
    return []


def transform_id(book_id):
    id_length = len(book_id)
    if re.match(r"^\d*$", book_id):
        ary = []
        for i in range(0, id_length, 9):
            ary.append(format(int(book_id[i: min(i + 9, id_length)]), "x"))
        return "3", ary

    result = ""
    for i in range(id_length):
        result += format(ord(book_id[i]), "x")
    return "4", [result]


def calculate_book_str_id(book_id):
    md5 = hashlib.md5()
    md5.update(book_id.encode("utf-8"))
    digest = md5.hexdigest()
    result = digest[0:3]
    code, transformed_ids = transform_id(book_id)
    result += code + "2" + digest[-2:]

    for i in range(len(transformed_ids)):
        hex_length_str = format(len(transformed_ids[i]), "x")
        if len(hex_length_str) == 1:
            hex_length_str = "0" + hex_length_str

        result += hex_length_str + transformed_ids[i]

        if i < len(transformed_ids) - 1:
            result += "g"

    if len(result) < 20:
        result += digest[0: 20 - len(result)]

    md5 = hashlib.md5()
    md5.update(result.encode("utf-8"))
    result += md5.hexdigest()[0:3]
    return result


def try_get_cloud_cookie(url, id, password):
    if url.endswith("/"):
        url = url[:-1]
    req_url = f"{url}/get/{id}"
    data = {"password": password}
    response = requests.post(req_url, data=data)
    if response.status_code != 200:
        return None
    data = response.json()
    cookie_data = data.get("cookie_data")
    if cookie_data and "weread.qq.com" in cookie_data:
        cookies = cookie_data["weread.qq.com"]
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        return cookie_str
    return None


def get_cookie():
    url = os.getenv("CC_URL") or "https://cookiecloud.malinkang.com/"
    cid = os.getenv("CC_ID")
    password = os.getenv("CC_PASSWORD")
    cookie = os.getenv("WEREAD_COOKIE")

    if url and cid and password:
        cloud = try_get_cloud_cookie(url, cid, password)
        if cloud:
            cookie = cloud

    if not cookie or not cookie.strip():
        raise Exception("没有找到cookie，请按照文档填写cookie")
    return cookie


def extract_page_id():
    # In this project, NOTION_PAGE is used as database id (or URL containing it)
    url = os.getenv("NOTION_PAGE", "").strip()

    if re.fullmatch(r"[0-9a-fA-F]{32}", url):
        return url.lower()

    if not url:
        raise Exception("没有找到 NOTION_PAGE，请检查 GitHub Secrets")

    match = re.search(r"[0-9a-fA-F]{32}", url)
    if match:
        return match.group(0).lower()

    raise Exception("获取 Notion ID 失败，请检查 NOTION_PAGE 是否正确")


# -----------------------------
# Notion minimal DB operations
# Requires ONLY:
# - BookId (Title)
# - Sort (Number)
# -----------------------------
def get_sort():
    """获取database中的最新Sort（数字）"""
    flt = {"property": "Sort", "number": {"is_not_empty": True}}
    sorts = [{"property": "Sort", "direction": "descending"}]
    response = client.databases.query(
        database_id=database_id, filter=flt, sorts=sorts, page_size=1
    )
    if len(response.get("results", [])) == 1:
        props = response["results"][0].get("properties", {})
        return props.get("Sort", {}).get("number") or 0
    return 0


def check(bookId):
    """检查是否已经插入过，如果已经插入就删除（按 Title 过滤）"""
    flt = {"property": "BookId", "title": {"equals": str(bookId)}}
    response = client.databases.query(database_id=database_id, filter=flt)
    for result in response.get("results", []):
        try:
            client.blocks.delete(block_id=result["id"])
        except Exception as e:
            print(f"删除块时出错: {e}")


def insert_to_notion(bookName, bookId, cover, sort, author, isbn, rating, categories):
    """精简版：只写 BookId(Title) + Sort(Number)，其他都不写"""
    parent = {"database_id": database_id, "type": "database_id"}
    properties = {
        "BookId": get_title(str(bookId)),   # MUST be Title column named BookId
        "Sort": get_number(int(sort)),      # MUST be Number column named Sort
    }
    # Avoid icon/cover to prevent type errors
    response = client.pages.create(parent=parent, properties=properties)
    return response["id"]


# -----------------------------
# Blocks (highlights & notes)
# -----------------------------
def add_children(page_id, children):
    results = []
    for i in range(0, len(children) // 100 + 1):
        time.sleep(0.3)
        response = client.blocks.children.append(
            block_id=page_id, children=children[i * 100: (i + 1) * 100]
        )
        results.extend(response.get("results", []))
    return results if len(results) == len(children) else None


def add_grandchild(grandchild, results):
    for key, value in grandchild.items():
        time.sleep(0.3)
        block_id = results[key].get("id")
        client.blocks.children.append(block_id=block_id, children=[value])


def get_children(chapter, summary, bookmark_list):
    children = []
    grandchild = {}

    if chapter is not None:
        children.append(get_table_of_contents())
        grouped = {}
        for data in bookmark_list:
            chapterUid = data.get("chapterUid", 1)
            grouped.setdefault(chapterUid, []).append(data)

        for ch_uid, items in grouped.items():
            if ch_uid in chapter:
                children.append(
                    get_heading(chapter[ch_uid].get("level"), chapter[ch_uid].get("title"))
                )
            for it in items:
                markText = it.get("markText", "")
                for j in range(0, len(markText) // 2000 + 1):
                    children.append(
                        get_callout(
                            markText[j * 2000: (j + 1) * 2000],
                            it.get("style"),
                            it.get("colorStyle"),
                            it.get("reviewId"),
                        )
                    )
                if it.get("abstract"):
                    grandchild[len(children) - 1] = get_quote(it.get("abstract"))
    else:
        for data in bookmark_list:
            markText = data.get("markText", "")
            for i in range(0, len(markText) // 2000 + 1):
                children.append(
                    get_callout(
                        markText[i * 2000: (i + 1) * 2000],
                        data.get("style"),
                        data.get("colorStyle"),
                        data.get("reviewId"),
                    )
                )

    if summary:
        children.append(get_heading(1, "点评"))
        for i in summary:
            content = i.get("review", {}).get("content", "")
            for j in range(0, len(content) // 2000 + 1):
                children.append(
                    get_callout(
                        content[j * 2000: (j + 1) * 2000],
                        i.get("style"),
                        i.get("colorStyle"),
                        i.get("review", {}).get("reviewId"),
                    )
                )

    return children, grandchild


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    _options = parser.parse_args()

    weread_cookie = get_cookie()
    database_id = extract_page_id()
    notion_token = os.getenv("NOTION_TOKEN")

    if not notion_token:
        raise Exception("没有找到 NOTION_TOKEN，请检查 GitHub Secrets")

    session = requests.Session()
    session.cookies = parse_cookie_string(weread_cookie)

    client = Client(auth=notion_token, log_level=logging.ERROR)

    # Warm up
    session.get(WEREAD_URL)

    latest_sort = get_sort()
    books = get_notebooklist()

    if books:
        for index, item in enumerate(books):
            sort = item.get("sort", 0)
            if sort <= latest_sort:
                continue

            book = item.get("book", {})
            title = book.get("title", "")
            cover = (book.get("cover") or "").replace("/s_", "/t7_")
            bookId = book.get("bookId")
            author = book.get("author")
            categories = book.get("categories")
            if categories:
                categories = [x.get("title") for x in categories if x.get("title")]

            print(f"正在同步 {title} ,一共{len(books)}本，当前是第{index+1}本。")

            # delete old page if exists
            check(bookId)

            # create minimal page record
            page_id = insert_to_notion(title, bookId, cover, sort, author, "", 0, categories)

            # fetch content blocks
            chapter = get_chapter_info(bookId)
            bookmark_list = get_bookmark_list(bookId) or []
            summary, reviews = get_review_list(bookId)
            bookmark_list.extend(reviews or [])

            bookmark_list = sorted(
                bookmark_list,
                key=lambda x: (
                    x.get("chapterUid", 1),
                    0 if (x.get("range", "") == "" or x.get("range").split("-")[0] == "")
                    else int(x.get("range").split("-")[0]),
                ),
            )

            children, grandchild = get_children(chapter, summary, bookmark_list)
            results = add_children(page_id, children)
            if grandchild and results is not None:
                add_grandchild(grandchild, results)
