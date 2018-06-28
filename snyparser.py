import os
import re
import json
import time
import peewee
import logging
import requests
from dateutil import parser
from lxml import html
from lxml.cssselect import CSSSelector
from datetime import datetime

from settings import SETTINGS

from model_snyk import SNYK

logging.basicConfig(format='%(name)s >> [%(asctime)s] :: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

debug = bool(SETTINGS.get("debug", True))

json_filename = SETTINGS.get("json_filename", "snyk.json")

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)

headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

GOLANG = "golang"
COMPOSER = "composer"
MAVEN = "maven"
NPM = "npm"
NUGET = "nuget"
PIP = "pip"
RUBYGEMS = "rubygems"

SOURCES = [GOLANG,
           # COMPOSER,
           # MAVEN,
           # NPM,
           # NUGET,
           # PIP,
           # RUBYGEMS
           ]

a_selector = CSSSelector('a')


def LOGINFO_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.info(message)

def LOGWARN_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.warning(message)

def LOGERR_IF_ENABLED(message="\n"):
    if enable_exception_logging:
        logger.error(message)

def LOGVAR_IF_ENABLED(message="\n"):
    if enable_results_logging:
        logger.info(message)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def create_url(num, lang):
    page_url = "https://snyk.io/vuln/page/{}?type={}".format(
        num, lang
    )
    LOGINFO_IF_ENABLED('[+] Get url: {}'.format(page_url))
    return page_url


def startswith(st, start):
    if str(st).startswith(start):
        return True
    return False


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def filter_vuln_links(links):
    fl = []
    for l in links:
        if startswith(l, "/vuln/SNYK-"):
            fl.append(l)
    return fl, len(fl)


def download_page_from_url(page_url):
    try:
        page = requests.get(page_url, headers=headers)
        LOGINFO_IF_ENABLED('[+] Response code: {}'.format(page.status_code))
        if page.status_code == 200:
            try:
                tree = html.fromstring(page.content)
                return tree
            except Exception as ex:
                LOGERR_IF_ENABLED("[-] Get an exception with download page from url: {}".format(ex))
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with requests get operation: {}".format(ex))
    return None


def parse_page(page_tree):
    try:
        header_title_list = page_tree.xpath('//span[@class="header__title__text"]/text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to header_title_list: {}".format(ex))
        header_title_list = []

    if len(header_title_list) > 0:
        header_title = str(header_title_list[0])
    else:
        header_title = "unknown"

    header_title = header_title.replace("\n", "")
    header_title = header_title.lstrip()
    header_title = header_title.rstrip()

    LOGINFO_IF_ENABLED("[v] TITLE: {}".format(header_title))

    try:
        affecting_list = page_tree.xpath('//a[@class="breadcrumbs__list-item__link"]/text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to affecting_list: {}".format(ex))
        affecting_list = []

    if len(affecting_list) >= 2:
        affecting_github = str(affecting_list[2])
    else:
        affecting_github = ""

    affecting_github = affecting_github.replace("\n", "")
    affecting_github = affecting_github.lstrip()
    affecting_github = affecting_github.rstrip()

    LOGINFO_IF_ENABLED("[v] AFFECTING: {}".format(affecting_github))

    try:
        versions_list = page_tree.xpath('//p[@class="header__lede"]//text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to versions_list: {}".format(ex))
        versions_list = []

    if len(versions_list) >= 5:
        versions = versions_list[4]
    else:
        versions = "undefined"

    versions = versions.replace("\n", "")
    versions = versions.lstrip()
    versions = versions.rstrip()

    LOGINFO_IF_ENABLED("[v] VERSIONS: {}".format(versions))

    try:
        overview_list = page_tree.xpath('//div[@class="card card--markdown"]//text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to overview_list: {}".format(ex))
        overview_list = []

    overview = ""
    is_overview = False
    remedation = ""
    is_remedation = False
    details = ""
    is_details = False
    for over in overview_list:
        if over == "Overview":
            is_overview = True
            is_remedation = False
            is_details = False
            continue
        elif over == "Remediation":
            is_overview = False
            is_remedation = True
            is_details = False
            continue
        elif over == "Details":
            is_overview = False
            is_remedation = False
            is_details = True

        if is_overview:
            overview += over
        elif is_remedation:
            remedation += over
        elif is_details:
            details += over

    if overview == "":
        overview = "undefined"

    overview = overview.replace("\n", " ")
    if overview == "":
        overview = "undefined"
    overview = overview.lstrip()
    overview = overview.rstrip()

    remedation = remedation.replace("\n", " ")
    if remedation == "":
        remedation = "undefined"
    remedation = remedation.lstrip()
    remedation = remedation.rstrip()

    details = details.replace("\n", " ")
    if details == "":
        details = "undefined"
    details = details.lstrip()
    details = details.rstrip()

    LOGINFO_IF_ENABLED("[v] OVERVIEW: {}".format(overview))
    LOGINFO_IF_ENABLED("[v] REMEDATION: {}".format(remedation))
    LOGINFO_IF_ENABLED("[v] DETAILS: {}".format(details))

    references_list_ul = []

    LOGINFO_IF_ENABLED("[v] REFERENCES:")
    try:
        r = page_tree.xpath('//h2[@id="references"]')[0].getnext().xpath('//li//a')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to references_list_ul: {}".format(ex))
        r = None

    if r is None:
        pass
    else:
        for _ in r:
            if _ is not None:
                if _.text is not None:
                    if "\n " not in _.text:
                        if "href" in _.attrib:
                            if "http://" in _.attrib["href"] or "https://" in _.attrib["href"]:
                                if "class" not in _.attrib:
                                    LOGINFO_IF_ENABLED("[v] " +_.text + ": " + _.attrib["href"])
                                    references_list_ul.append(json.dumps(
                                        {
                                            "name": _.text,
                                            "ref": _.attrib["href"]
                                        }
                                    ))

    try:
        card__content = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to card__content: {}".format(ex))
        card__content = []

    credit = "undefined"
    snyk_id = "undefined"
    disclosed_str = "undefined"
    published_str = "undefined"
    disclosed_dt = datetime.utcnow()
    published_dt = datetime.utcnow()

    if len(card__content) >= 6:
        credit = str(card__content[0].text.replace("\n", "")).strip()
        credit = credit.lstrip()
        credit = credit.rstrip()

        snyk_id = str(card__content[3].text.replace("\n", "")).strip()
        snyk_id = snyk_id.lstrip()
        snyk_id = snyk_id.rstrip()

        disclosed_str = str(card__content[4].text.replace("\n", "")).strip()
        disclosed_str = disclosed_str.lstrip()
        disclosed_str = disclosed_str.rstrip()
        disclosed_dt = parser.parse(disclosed_str)


        published_str = str(card__content[5].text.replace("\n", "")).strip()
        published_str = published_str.lstrip()
        published_str = published_str.rstrip()
        published_dt = parser.parse(published_str)

    LOGINFO_IF_ENABLED("[v] CREDIT: {}".format(credit))
    LOGINFO_IF_ENABLED("[v] SNYK ID: {}".format(snyk_id))
    LOGINFO_IF_ENABLED("[v] DISCLOSED: {}".format(disclosed_dt))
    LOGINFO_IF_ENABLED("[v] PUBLISHED: {}".format(published_dt))

    cve = "undefined"
    cve_url = "undefined"
    cwe = "undefined"
    cwe_url = "undefined"

    try:
        card__content_a = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd/a')
    except Exception as ex:
        LOGERR_IF_ENABLED("[-] Get an exception with xpath to card__content_a: {}".format(ex))
        card__content_a = []

    if len(card__content_a) >= 2:
        cve_a = card__content_a[0].attrib
        if "href" in cve_a:
            if "cve.mitre.org" in cve_a["href"] or \
                    "nvd.nist.gov" in cve_a["href"] or \
                    "cloudfoundry.org" in cve_a["href"]:
                cve_url = cve_a["href"]
                try:
                    i = cve_url.index("CVE-20")
                    cve = cve_url[i:]
                except ValueError as ve:
                    cve = "undefined"
                if not startswith(cve, "CVE-"):
                    cve = "undefined"
            else:
                cve_url = cve = "undefined"
        else:
            cve_url = cve = "undefined"

        cwe_a = card__content_a[1].attrib
        if "href" in cwe_a:
            if "cwe.mitre.org" in cwe_a["href"]:
                cwe_url = cwe_a["href"]
                cwe = find_between(cwe_url, "https://cwe.mitre.org/data/definitions/", ".html")
                if cwe != "":
                    cwe = re.sub("\D", "", str(cwe))
                    cwe = "CWE-" + cwe
                else:
                    cwe = "undefined"
            else:
                cwe_url = cwe = "undefined"
        else:
            cwe_url = cwe = "undefined"

    LOGINFO_IF_ENABLED("[v] CVE: {}".format(cve))
    LOGINFO_IF_ENABLED("[v] CVE URL: {}".format(cve_url))

    LOGINFO_IF_ENABLED("[v] CWE: {}".format(cwe))
    LOGINFO_IF_ENABLED("[v] CWE URL: {}".format(cwe_url))

    return dict(
        header_title=header_title,
        affecting_github=affecting_github,
        versions=versions,
        overview=overview,
        details=details,
        references=references_list_ul,
        cve_id=cve,
        cve_url=cve_url,
        cwe_id=cwe,
        cwe_url=cwe_url,
        credit=credit,
        snyk_id=snyk_id,
        disclosed=disclosed_str,
        published=published_str,
        source="",
        source_url="",
        type=""
    )

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgress database")
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Connect Postgres database error: {}".format(peewee_operational_error))
    return False


def disconnect_database():
    try:
        if database.is_closed():
            pass
        else:
            database.close()
        LOGVAR_IF_ENABLED("[+] Disconnect Postgress database")
        peewee.logger.disabled = False
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[-] Disconnect Postgres database error: {}".format(peewee_operational_error))
    peewee.logger.disabled = False
    return False

def drop_snyk_table():
    connect_database()
    if SNYK.table_exists():
        SNYK.drop_table()
    disconnect_database()

def create_snyk_table():
    connect_database()
    if not SNYK.table_exists():
        SNYK.create_table()
    disconnect_database()

def count_snyk_table():
    connect_database()
    count = SNYK.select().count()
    if count:
        disconnect_database()
        return count
    return 0

def create_snyk_item_in_postgres(item_in_json):
    connect_database()
    sid = 0

    # TODO: Clearup all fields lstrip/rstrip

    item_in_json["disclosed"] = datetime.utcnow() if item_in_json["disclosed"] == "undefined" else item_in_json["disclosed"]
    item_in_json["published"] = datetime.utcnow() if item_in_json["published"] == "undefined" else item_in_json["published"]


    snyk = SNYK(
        type=str(item_in_json["type"]),
        cve_id=str(item_in_json["cve_id"]),
        cve_url=str(item_in_json["cve_url"]),
        cwe_id=str(item_in_json["cwe_id"]),
        cwe_url=str(item_in_json["cwe_url"]),
        header_title=str(item_in_json["header_title"]),
        affecting_github=str(item_in_json["affecting_github"]),
        versions=str(item_in_json["versions"]),
        overview=str(item_in_json["overview"]),
        details=str(item_in_json["details"]),
        references=str(item_in_json["references"]),
        credit=str(item_in_json["credit"]),
        snyk_id=str(item_in_json["snyk_id"]),
        source=str(item_in_json["source"]),
        source_url=str(item_in_json["source_url"]),
        disclosed=str(item_in_json["disclosed"]),
        published=str(item_in_json["published"])
    )
    snyk.save()

    disconnect_database()
    return sid

def update_snyk_item_in_postgres(item_in_json, sid):
    connect_database()

    snyk = SNYK.get_by_id(sid)

    modified = False

    if snyk.type != item_in_json["type"] or \
            snyk.cve_id != item_in_json["cve_id"] or \
        snyk.cve_url != item_in_json["cve_url"]or \
        snyk.cwe_id != item_in_json["cwe_id"] or \
        snyk.cwe_url != item_in_json["cwe_url"] or \
        snyk.header_title != item_in_json["header_title"] or \
        snyk.affecting_github != item_in_json["affecting_github"] or \
        snyk.versions != item_in_json["versions"] or \
        snyk.overview != item_in_json["overview"] or \
        snyk.details != item_in_json["details"] or \
        snyk.references != item_in_json["references"] or \
        snyk.credit != item_in_json["credit"] or \
        snyk.snyk_id != item_in_json["snyk_id"] or \
        snyk.source != item_in_json["source"] or \
        snyk.source_url != item_in_json["source_url"]:
        modified = True

    if modified:
        item_in_json["disclosed"] = datetime.utcnow() if item_in_json["disclosed"] == "undefined" else item_in_json["disclosed"]
        item_in_json["published"] = datetime.utcnow() if item_in_json["published"] == "undefined" else item_in_json["published"]
        snyk.type = item_in_json["type"]
        snyk.cve_id = item_in_json["cve_id"]
        snyk.cve_url = item_in_json["cve_url"]
        snyk.cwe_id = item_in_json["cwe_id"]
        snyk.cwe_url = item_in_json["cwe_url"]
        snyk.header_title = item_in_json["header_title"]
        snyk.affecting_github = item_in_json["affecting_github"]
        snyk.versions = item_in_json["versions"]
        snyk.overview = item_in_json["overview"]
        snyk.details = item_in_json["details"]
        snyk.references = item_in_json["references"]
        snyk.credit = item_in_json["credit"]
        snyk.snyk_id = item_in_json["snyk_id"]
        snyk.source = item_in_json["source"]
        snyk.source_url = item_in_json["source_url"]
        snyk.disclosed = item_in_json["disclosed"]
        snyk.published = item_in_json["published"]
        snyk.save()
        disconnect_database()
        return True
    else:
        disconnect_database()
        return False

def check_if_snyk_item_exists_in_postgres(item_in_json):
    connect_database()
    sid = -1
    snyks = []

    # if "cve_id" in item_in_json and "header_title" in item_in_json:
        # cve_id = item_in_json["cve_id"]
        # header_title = item_in_json["header_title"]
    if "snyk_id" in item_in_json:
        snyk_id = item_in_json["snyk_id"]
        snyks = list(
            SNYK.select().where(
                # (SNYK.cve_id == cve_id) & (SNYK.header_title == header_title) & (SNYK.snyk_id == snyk_id)
                (SNYK.snyk_id == snyk_id)
            )
        )

    if len(snyks) == 0:
        disconnect_database()
        return False, sid
    else:
        sid = snyks[0].to_json["id"]
        disconnect_database()
        return True, sid

def create_or_update_snyk_items_in_postgres(items_in_json):
    created = []
    updated = []
    skipped = []
    for item in items_in_json:
        exists, sid = check_if_snyk_item_exists_in_postgres(item)
        if exists:
            modified = update_snyk_item_in_postgres(item, sid)
            if modified:
                updated.append(item)
            else:
                skipped.append(item)
        else:
            sid = create_snyk_item_in_postgres(item)
            created.append(item)
    return created, updated, skipped


def create_or_update_one_snyk_item_in_postgres(item_in_json):
    exists, sid = check_if_snyk_item_exists_in_postgres(item_in_json)
    if not exists and sid == -1:
        sid = create_snyk_item_in_postgres(item_in_json)
        return "created"
    else:
        modified = update_snyk_item_in_postgres(item_in_json, sid)
        if modified:
            return "modified"
        else:
            return "skipped"


def populate_snyk_vulners():
    count = count_snyk_table()

    if count == 0:
        LOGINFO_IF_ENABLED("[+] Start populating Snyk vulnerabilities")
        start_time = time.time()
        drop_snyk_table()
        create_snyk_table()
        snyk_count = 0
        for source in SOURCES:
            continue_work = True
            page_number = 1
            LOGINFO_IF_ENABLED("[+] Process source `{}`".format(source))
            while continue_work:
                LOGINFO_IF_ENABLED("[+] Process page # {}".format(page_number))
                page_url = create_url(page_number, source)
                tree = download_page_from_url(page_url)
                if tree is not None:
                    try:
                        f = a_selector(tree)
                        links = [e.get('href') for e in f]
                        filtered_links, cnt = filter_vuln_links(links)
                        LOGINFO_IF_ENABLED("[+] Get {} valid snyk links from page".format(cnt))
                    except Exception as ex:
                        LOGERR_IF_ENABLED("[-] Get an exception with tree parsing: {}".format(ex))
                        return False
                if len(filtered_links) == 0:
                    LOGINFO_IF_ENABLED("[+] Complete parsing source `{}`".format(source))
                    continue_work = False
                else:
                    for pn in range(len(filtered_links)):
                        LOGINFO_IF_ENABLED("[+] Parse vulner # {}".format(pn))
                        d_url = "".join(["https://snyk.io", filtered_links[pn]])
                        page_tree = download_page_from_url(d_url)
                        if page_tree is not None:
                            snyk_vulner = parse_page(page_tree)
                            snyk_vulner["source"] = "snyk"
                            snyk_vulner["source_url"] = d_url
                            snyk_vulner["type"] = source

                            result = create_or_update_one_snyk_item_in_postgres(snyk_vulner)
                            snyk_count += 1

                page_number += 1

        LOGINFO_IF_ENABLED("[+] Complete populating {} Snyk vulnerabilities at {} sec.".format(snyk_count, time.time() - start_time))
        return True
    else:
        LOGINFO_IF_ENABLED("[-] You want populate Snyk vulnerabilities, but Snyk table is not empty.")
        return False

def update_snyk_vulners():
    count = count_snyk_table()
    if count == 0:
        LOGINFO_IF_ENABLED("[-] You want populate Snyk vulnerabilities, but Snyk table is empty. Needs to populate it.")
        return False, []
    else:
        start_time = time.time()
        created_snyk_vulners = []
        for source in SOURCES:
            continue_work = True
            page_number = 1
            LOGINFO_IF_ENABLED("[+] Process source `{}`".format(source))
            while continue_work:
                LOGINFO_IF_ENABLED("[+] Process page # {}".format(page_number))
                page_url = create_url(page_number, source)
                tree = download_page_from_url(page_url)
                if tree is not None:
                    try:
                        f = a_selector(tree)
                        links = [e.get('href') for e in f]
                        filtered_links, cnt = filter_vuln_links(links)
                        LOGINFO_IF_ENABLED("[+] Get {} valid snyk links from page".format(cnt))
                    except Exception as ex:
                        LOGERR_IF_ENABLED("[-] Get an exception with tree parsing: {}".format(ex))
                        return False, []
                if len(filtered_links) == 0:
                    LOGINFO_IF_ENABLED("[+] Complete parsing source `{}`".format(source))
                    continue_work = False
                else:
                    for pn in range(len(filtered_links)):
                        LOGINFO_IF_ENABLED("[+] Parse vulner # {}".format(pn))
                        d_url = "".join(["https://snyk.io", filtered_links[pn]])
                        page_tree = download_page_from_url(d_url)
                        if page_tree is not None:
                            snyk_vulner = parse_page(page_tree)
                            snyk_vulner["source"] = "snyk"
                            snyk_vulner["source_url"] = d_url
                            snyk_vulner["type"] = source

                            exists, sid = check_if_snyk_item_exists_in_postgres(snyk_vulner)

                            if exists and sid != -1:
                                continue_work = False
                            elif not exists and sid == -1:
                                created_snyk_vulners.append(snyk_vulner)
                                result = create_or_update_one_snyk_item_in_postgres(snyk_vulner)
                                LOGINFO_IF_ENABLED("[F] Find new Snyk vulnerability: {}".format(snyk_vulner["header_title"]))
                page_number += 1

        LOGINFO_IF_ENABLED("[+] Complete updating {} Snyk vulnerabilities at {} sec.".format(len(created_snyk_vulners), time.time() - start_time))
        return True, created_snyk_vulners

def run():
    drop_snyk_table()
    create_snyk_table()

    populate_snyk_vulners()
    update_snyk_vulners()
    pass


def main():
    run()


if __name__ == "__main__":
    main()
