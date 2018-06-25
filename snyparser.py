from lxml import html
from lxml.cssselect import CSSSelector
import requests
import re
import sys
import time
import json
from datetime import datetime

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

json_filename = "snyk.json"


def LOGINFO_IF_ENABLED(message="\n"):
    print(message)


def LOGERR_IF_ENABLED(message="\n"):
    print(message)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def create_url(num, lang):
    page_url = "https://snyk.io/vuln/page/{}?type={}".format(
        num, lang
    )
    LOGINFO_IF_ENABLED('Get url: {}'.format(page_url))
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
        print('Response code: {}'.format(page.status_code))
        if page.status_code == 200:
            try:
                tree = html.fromstring(page.content)
                return tree
            except Exception as ex:
                LOGERR_IF_ENABLED("Get an exception with download page from url: {}".format(ex))
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with requests get operation: {}".format(ex))
    return None


def parse_page(page_tree):
    try:
        header_title_list = page_tree.xpath('//span[@class="header__title__text"]/text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to header_title_list: {}".format(ex))
        header_title_list = []

    if len(header_title_list) > 0:
        header_title = header_title_list[0]
    else:
        header_title = "unknown"

    LOGINFO_IF_ENABLED("TITLE: {}".format(header_title))

    try:
        affecting_list = page_tree.xpath('//a[@class="breadcrumbs__list-item__link"]/text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to affecting_list: {}".format(ex))
        affecting_list = []

    if len(affecting_list) >= 2:
        affecting_github = affecting_list[2]
    else:
        affecting_github = ""

    LOGINFO_IF_ENABLED("AFFECTING: {}".format(affecting_github))

    try:
        versions_list = page_tree.xpath('//p[@class="header__lede"]//text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to versions_list: {}".format(ex))
        versions_list = []

    if len(versions_list) >= 5:
        versions = versions_list[4]
    else:
        versions = "undefined"

    LOGINFO_IF_ENABLED("VERSIONS: {}".format(versions))

    try:
        overview_list = page_tree.xpath('//div[@class="card card--markdown"]//text()')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to overview_list: {}".format(ex))
        overview_list = []

    overview = ""
    is_overview = False
    remedation = ""
    is_remedation = False
    for over in overview_list:
        if over == "Overview":
            is_overview = True
            is_remedation = False
            continue
        elif over == "Remediation":
            is_overview = False
            is_remedation = True
            continue

        if is_overview:
            overview += over
        elif is_remedation:
            remedation += over

    overview = overview.replace("\n", " ")
    remedation = remedation.replace("\n", " ")
    if remedation == "":
        remedation = "undefined"

    LOGINFO_IF_ENABLED("OVERVIEW: {}".format(overview))
    LOGINFO_IF_ENABLED("REMEDATION: {}".format(remedation))

    references_list_ul = []

    LOGINFO_IF_ENABLED("REFERENCES:")
    try:
        r = page_tree.xpath('//h2[@id="references"]')[0].getnext().xpath('//li//a')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to references_list_ul: {}".format(ex))
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
                                    print(_.text, ": ", _.attrib["href"])
                                    references_list_ul.append({
                                        "name": _.text,
                                        "ref": _.attrib["href"]
                                    })

    try:
        card__content = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to card__content: {}".format(ex))
        card__content = []

    credit = "unknown"
    snyk_id = "undefined"
    disclosed = "undefined"
    published = "undefined"
    if len(card__content) >=6:
        credit = card__content[0].text.replace("\n", "").strip()
        snyk_id = card__content[3].text.replace("\n", "").strip()
        disclosed = card__content[4].text.replace("\n", "").strip()
        published = card__content[5].text.replace("\n", "").strip()

    LOGINFO_IF_ENABLED("CREDIT: {}".format(credit))
    LOGINFO_IF_ENABLED("SNYK ID: {}".format(snyk_id))
    LOGINFO_IF_ENABLED("DISCLOSED: {}".format(disclosed))
    LOGINFO_IF_ENABLED("PUBLISHED: {}".format(published))

    cve = ""
    cve_url = ""
    cwe = ""
    cwe_url = ""

    try:
        card__content_a = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd/a')
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception with xpath to card__content_a: {}".format(card__content_a))
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
                    cve = ""

        cwe_a = card__content_a[1].attrib
        if "href" in cwe_a:
            if "cwe.mitre.org" in cwe_a["href"]:
                cwe_url = cwe_a["href"]
                cwe = find_between(cwe_url, "https://cwe.mitre.org/data/definitions/", ".html")
                if cwe != "":
                    cwe = re.sub("\D", "", str(cwe))
                    cwe = "CWE-" + cwe

    LOGINFO_IF_ENABLED("CVE: {}".format(cve))
    LOGINFO_IF_ENABLED("CVE URL: {}".format(cve_url))

    LOGINFO_IF_ENABLED("CWE: {}".format(cwe))
    LOGINFO_IF_ENABLED("CWE URL: {}".format(cwe_url))

    return dict(
        header_title=header_title,
        affecting_github=affecting_github,
        versions=versions,
        overview=overview,
        references=references_list_ul,
        cve=cve,
        cve_url=cve_url,
        cwe=cwe,
        cwe_url=cwe_url,
        credit=credit,
        snyk_id=snyk_id,
        disclosed=disclosed,
        published=published
    )


def download_and_parse_snyk_vulners():
    snyk_vulners = []

    LOGINFO_IF_ENABLED("Snyk parser started...")
    for source in SOURCES:

        work = True
        num = 1

        LOGINFO_IF_ENABLED()
        LOGINFO_IF_ENABLED("Process source `{}`".format(source))
        LOGINFO_IF_ENABLED()

        while work:
            LOGINFO_IF_ENABLED()
            LOGINFO_IF_ENABLED("Process page num {}".format(num))
            LOGINFO_IF_ENABLED()

            page_url = create_url(num, source)
            tree = download_page_from_url(page_url)
            if tree is not None:
                try:
                    f = a_selector(tree)
                    links = [e.get('href') for e in f]
                    filtered_links, cnt = filter_vuln_links(links)
                    LOGINFO_IF_ENABLED("Get {} valid snyk links from page".format(cnt))
                except Exception as ex:
                    LOGERR_IF_ENABLED("Get an exception with tree parsing: {}".format(ex))
                    sys.exit(1)

            if len(filtered_links) == 0:
                LOGINFO_IF_ENABLED()
                LOGINFO_IF_ENABLED("Complete parsing source `{}`".format(source))
                LOGINFO_IF_ENABLED()
                work = False
            else:
                for pn in range(len(filtered_links)):
                    LOGINFO_IF_ENABLED()
                    LOGINFO_IF_ENABLED("Parse vulner # {}".format(pn))
                    LOGINFO_IF_ENABLED()
                    d_url = "".join(["https://snyk.io", filtered_links[pn]])
                    page_tree = download_page_from_url(d_url)
                    if page_tree is not None:
                        parsed_page = parse_page(page_tree)
                        parsed_page["source"]="snyk"
                        parsed_page["source_url"] = d_url

                        snyk_vulners.append(parsed_page)

            num += 1

        LOGINFO_IF_ENABLED("Pause...")
        time.sleep(5)

    return snyk_vulners

def main():
    snyk_vulners = download_and_parse_snyk_vulners()
    LOGINFO_IF_ENABLED()
    LOGINFO_IF_ENABLED("Complete parsing {} snyk vulners".format(len(snyk_vulners)))
    LOGINFO_IF_ENABLED()

    result_json = dict(
        source="https://snyk.io",
        datetime=str(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        data=snyk_vulners
    )

    try:
        with open(json_filename, 'w') as jf:
            json.dump(result_json, jf, default=set_default)
        LOGINFO_IF_ENABLED("File {} with result_json was dumped".format(json_filename))
    except Exception as ex:
        LOGERR_IF_ENABLED("Get an exception writing json file with result_json: {}".format(ex))

    LOGINFO_IF_ENABLED("Job complete...")


if __name__ == "__main__":
    main()
