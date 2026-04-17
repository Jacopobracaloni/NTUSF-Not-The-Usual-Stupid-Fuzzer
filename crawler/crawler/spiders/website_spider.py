import scrapy
from scrapy.downloadermiddlewares.cookies import CookieJar
from urllib.parse import urlparse, parse_qs, urlsplit, unquote, urlencode, urlunparse
import sys
import re
import json
import os
import sys


class Crawler(scrapy.Spider):
    def __init__(
        self,
        username=None,
        password=None,
        login_url=None,
        proxies=None,
        param_limit=10,
        username_field=None,
        password_field=None,
        additional_login_params=None,
        csrf_token_name="csrf-token",
        exclude_paths=["logout.php"],
        *args,
        **kwargs,
    ):
        super(Crawler, self).__init__(*args, **kwargs)
        self.has_error = False
        self.username = username
        self.password = password
        self.login_url = login_url
        self.csrf_token_name = csrf_token_name
        self.exclude_paths = exclude_paths
        self.username_field = username_field if username_field else "username"
        self.password_field = password_field if password_field else "password"
        self.additional_login_params = (
            additional_login_params if additional_login_params else {}
        )
        self.proxies = proxies
        self.param_limit = param_limit
        self.param_counts = {}
        self.scheme = ""
        self.netloc = ""
        if (
            "csrf_token_name" in kwargs
            or "exclude_paths" in kwargs
            or "start_urls" in kwargs
        ):
            self.csrf_token_name = kwargs["csrf_token_name"]
            exclude_paths = [path for path in kwargs["exclude_paths"]]
            self.allowed_domains = [
                urlsplit(url).hostname for url in kwargs["start_urls"]
            ]

    visited_forms = set()
    name = "website_crawler"

    def start_requests(self):
        proxy = {"proxy": self.proxies, "dont_verify_ssl": True}
        # Check if login_url, username, and password are provided
        if self.login_url and self.username and self.password:
            # Start with the login page
            yield scrapy.Request(self.login_url, callback=self.parse_login, meta=proxy)
        else:
            # If not, start with the URLs provided
            for url in self.start_urls:
                parsed_url = urlparse(url)
                self.netloc, self.scheme = parsed_url.netloc, parsed_url.scheme
                yield scrapy.Request(url, callback=self.parse, meta=proxy)

    def save_cookies(self, cookies):
        # Save the cookies to a file
        file_path = os.path.join(sys.path[0], "cookies.json")
        with open(file_path, "w") as f:
            json.dump(cookies, f)

    def parse_login(self, response):
        proxy = {"proxy": self.proxies, "dont_verify_ssl": True}

        csrf_token = response.xpath(
            f'//*[@name="{self.csrf_token_name}"]/@value'
        ).extract_first()
        self.logger.info(csrf_token)
        login_data = {
            self.username_field: self.username,
            self.password_field: self.password,
        }
        if csrf_token:
            login_data[f"{self.csrf_token_name}"] = csrf_token

        # Add additional login parameters
        login_data.update(self.additional_login_params)
        common_meta = {"dont_verify_ssl": True}

        if self.proxies:
            common_meta["proxy"] = self.proxies

        yield scrapy.FormRequest(
            response.url,
            formdata=login_data,
            meta=proxy,
            callback=self.parse,
            dont_filter=True,
        )

    def should_exclude(self, url):
        url = unquote(url.lower())
        for excluded_path in self.exclude_paths:
            if excluded_path.lower() in url:
                return True
        return False

    def ensure_full_url(self, url):
        if not urlparse(url).scheme:
            return urlunparse((self.scheme, self.netloc, url, "", "", ""))
        return url

    def parse(self, response):
        try:
            common_meta = {"dont_verify_ssl": True}

            if self.proxies:
                common_meta["proxy"] = self.proxies

            # Update for GET parameters
            get_params = parse_qs(urlparse(response.url).query)
            self.logger.info(response.url)

            yield {
                "URL": response.url,
                "base_url": urlparse(response.url).netloc,
                "Method": "POST" if "POST Params" in response.meta else "GET",
                "GET Params": get_params,
                "POST Params": response.meta.get("POST Params")
                if "POST Params" in response.meta
                else None,
            }

            for href in response.css("a::attr(href)").getall():
                full_url = self.ensure_full_url(response.urljoin(href))

                if self.should_exclude(full_url):
                    continue

                if not self.is_valid_url(full_url):
                    self.logger.error(f"Invalid URL: {full_url}")
                    continue

                yield scrapy.Request(
                    full_url,
                    callback=self.parse,
                    meta=common_meta,
                    dont_filter=False,
                )

            for form in response.css("form"):
                formdata = {}
                action = form.css("::attr(action)").get()
                method = form.css("::attr(method)").get() or "GET"
                input_names = []

                for input in form.css("input"):
                    input_name = input.css("::attr(name)").get()
                    input_value = input.css("::attr(value)").get() or ""
                    if input_name:
                        formdata[input_name] = input_value
                        input_names.append(input_name)

                form_fingerprint = (response.url, tuple(sorted(input_names)))
                if form_fingerprint in self.visited_forms:
                    continue

                self.visited_forms.add(form_fingerprint)

                if action == "#":
                    action = self.ensure_full_url(response.url)

                if method.lower() == "get":
                    query_params = {key: [value] for key, value in formdata.items()}
                    url_with_params = f"{action}?{urlencode(query_params, doseq=True)}"
                    url_with_params = self.ensure_full_url(url_with_params)
                    if self.should_exclude(url_with_params):
                        continue
                    yield scrapy.Request(
                        url=url_with_params,
                        callback=self.parse,
                        meta=common_meta,
                        dont_filter=False,
                    )

                elif method.lower() == "post":
                    post_meta = common_meta.copy()
                    post_meta["POST Params"] = formdata
                    action_url = self.ensure_full_url(response.urljoin(action))
                    if self.should_exclude(action_url):
                        continue
                    yield scrapy.FormRequest(
                        url=action_url,
                        formdata=formdata,
                        callback=self.parse,
                        meta=post_meta,
                        dont_filter=False,
                    )
        except KeyboardInterrupt:
            sys.exit(0)
