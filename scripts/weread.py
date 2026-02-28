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
    get_quote,
    get_table_of_contents,
)

load_dotenv()

WEREAD_URL = "https://weread.qq.com/"
WEREAD_NOTEBOOKS_URL = "https://weread.qq.com/api/user/notebook"
WEREAD_BOOKMARKLIST_URL = "https://weread.qq.com/web/book/bookmarklist"
WEREAD_CHAPTER_INFO = "https://weread.qq.com/web/book/chapterInfos"
WEREAD_READ_INFO_URL = "https://weread.qq.com/web/book/readinfo"
WEREAD_REVIEW_LIST_URL = "https://weread.qq.com/web/review/list"
WEREAD_BOOK_INFO = "https://weread.qq.com/web/book/info"


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
    session.get(WEREAD_URL)
    return True


@retry(stop_max_attempt_number=3, wait_fixed=5000, retry_on_exception=refresh_token)
def get_bookmark_list(bookId):
    """获取我的划线"""
    session.get(WEREAD_URL)
    params = dict(bookId=bookId)
    r = session.get(WEREAD_BOOKMARKLIST_URL, params=params)
    if r.ok:
        updated = r.json().get("updated", []) or []
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
    """获取书的详情（本版本不写入 Notion，仅保留函数，避免影响主流程）"""
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
    else:
        print(r.text)
    return []


def transform_id(book_id):
    id_length = len(book_id)

    if re.match(r"^\d*$", book_id):
        ary = []
        for i in range(0, id_length, 9):
            ary.append(format(int(book_id[i : min(i + 9, id_length)]), "x"))
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
        result += digest[0 : 20 - len(result)]

    md5 = hashlib.md5()
    md5.update(result.encode("utf-8"))
    result += md5.hexdigest()[0:3]
    return result


def try_get_cloud_cookie(url, cid, password):
    if url.endswith("/"):
        url = url[:-1]
    req_url = f"{url}/get/{cid}"
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
    """
    NOTION_PAGE 这里实际存的是“数据库URL或数据库ID”
    - 如果直接给 32 位 ID：直接用
    - 如果给 URL：从中提取 32 位 ID
    """
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
# Notion DB operations (7 fields)
# -----------------------------
def get_sort():
    """获取 database 里 Sort 最大值，用于增量同步"""
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
    """检查是否已经插入过，如果插入过就删除（BookId 是 Title）"""
    flt = {"property": "BookId", "title": {"equals": str(bookId)}}
    response = client.databases.query(database_id=database_id, filter=flt)
    for result in response.get("results", []):
        try:
            client.blocks.delete(block_id=result["id"])
        except Exception as e:
            print(f"删除块时出错: {e}")


def insert_to_notion(bookName, bookId, cover, sort, author, isbn, rating, categories):
    """
    只写 7 个字段：
    BookId(Title), BookName(Text), Author(Text), Cover(Files), Status(Select), Sort(Number), Categories(Multi-select)
    """
    parent = {"database_id": database_id, "type": "database_id"}

    # 封面兜底
    if not cover or not str(cover).startswith("http"):
        cover = "https://www.notion.so/icons/book_gray.svg"

    # 阅读状态（在读/读完）
    status_name = "在读"
    read_info = get_read_info(bookId=bookId)
    if read_info:
        markedStatus = read_info.get("markedStatus", 0)
        status_name = "读完" if markedStatus == 4 else "在读"

    properties = {
        "BookId": {"title": [{"text": {"content": str(bookId)}}]},
        "BookName": {"rich_text": [{"text": {"content": str(bookName or "")}}]},
        "Author": {"rich_text": [{"text": {"content": str(author or "")}}]},
        "Sort": {"number": int(sort) if sort is not None else 0},
        "Status": {"select": {"name": status_name}},
        "Cover": {
            "files": [
                {"name": "cover", "type": "external", "external": {"url": str(cover)}}
            ]
        },
    }

    if categories:
        properties["Categories"] = {
            "multi_select": [{"name": str(x)} for x in categories if x]
        }

    # 不设置页面 icon/cover，避免额外类型问题（封面已作为属性写入 Cover）
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
            block_id=page_id, children=children[i * 100 : (i + 1) * 100]
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
        # 目录
        children.append(get_table_of_contents())
        d = {}
        for data in bookmark_list:
            chapterUid = data.get("chapterUid", 1)
            d.setdefault(chapterUid, []).append(data)

        for key, value in d.items():
            if key in chapter:
                children.append(
                    get_heading(
                        chapter.get(key).get("level"), chapter.get(key).get("title")
                    )
                )
            for i in value:
                markText = i.get("markText", "")
                for j in range(0, len(markText) // 2000 + 1):
                    children.append(
                        get_callout(
                            markText[j * 2000 : (j + 1) * 2000],
                            i.get("style"),
                            i.get("colorStyle"),
                            i.get("reviewId"),
                        )
                    )
                if i.get("abstract"):
                    quote = get_quote(i.get("abstract"))
                    grandchild[len(children) - 1] = quote
    else:
        # 没章节信息
        for data in bookmark_list:
            markText = data.get("markText", "")
            for i in range(0, len(markText) // 2000 + 1):
                children.append(
                    get_callout(
                        markText[i * 2000 : (i + 1) * 2000],
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
                        content[j * 2000 : (j + 1) * 2000],
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

    session.get(WEREAD_URL)

    latest_sort = get_sort()
    books = get_notebooklist()

    if books:
        for index, item in enumerate(books):
            sort = item.get("sort", 0)
            if sort <= latest_sort:
                continue

            book = item.get("book", {}) or {}
            title = book.get("title", "")
            cover = (book.get("cover") or "").replace("/s_", "/t7_")
            bookId = book.get("bookId")
            author = book.get("author", "")
            categories = book.get("categories")
            if categories:
                categories = [x.get("title") for x in categories if x.get("title")]

            print(f"正在同步 {title} ,一共{len(books)}本，当前是第{index+1}本。")

            check(bookId)

            page_id = insert_to_notion(
                title, bookId, cover, sort, author, "", 0, categories
            )

            chapter = get_chapter_info(bookId)
            bookmark_list = get_bookmark_list(bookId) or []
            summary, reviews = get_review_list(bookId)
            bookmark_list.extend(reviews or [])

            bookmark_list = sorted(
                bookmark_list,
                key=lambda x: (
                    x.get("chapterUid", 1),
                    (
                        0
                        if (
                            x.get("range", "") == ""
                            or x.get("range").split("-")[0] == ""
                        )
                        else int(x.get("range").split("-")[0])
                    ),
                ),
            )

            children, grandchild = get_children(chapter, summary, bookmark_list)
            results = add_children(page_id, children)
            if grandchild and results is not None:
                add_grandchild(grandchild, results)
