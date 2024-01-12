# adapted from https://github.com/bugcrowd/HUNT

from bbot.modules.base import BaseModule
import re

from bbot.core.helpers.misc import extract_params_html


class BaseLightfuzz:
    def __init__(self, parent, event):
        self.parent = parent
        self.event = event
        self.results = []

    async def send_probe(self, probe):
        getparams = {self.event.data["name"]: probe}
        url = self.parent.helpers.add_get_params(self.event.data["url"], getparams).geturl()

        self.parent.debug(f"lightfuzz sending probe with URL: {url}")

        r = await self.parent.helpers.request(method="GET", url=url, allow_redirects=False, retries=2, timeout=10)
        if r:
            return r.text


class SQLiLightfuzz(BaseLightfuzz):
    async def fuzz(self):
        self.parent.critical(self.event.data["type"])

        probe_value = self.event.data.get("original_value", self.parent.helpers.rand_string(8))

        if self.event.data["type"] == "GETPARAM":
            baseline_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}"
        else:
            baseline_url = self.event.data["url"]

        self.parent.hugeinfo("baseline URL")
        self.parent.hugewarning(baseline_url)

        if self.event.data["type"] == "GETPARAM":
            http_compare = self.parent.helpers.http_compare(baseline_url, include_cache_buster=False)
        elif self.event.data["type"] == "COOKIE":
            cookies = {self.event.data["name"]: f"{self.event.data['original_value']}"}
            http_compare = self.parent.helpers.http_compare(baseline_url, include_cache_buster=False, cookies=cookies)

        elif self.event.data["type"] == "HEADER":
            pass

        # Add Single Quote

        if self.event.data["type"] == "COOKIE":
            cookies = {self.event.data["name"]: f"{self.event.data['original_value']}'"}
            single_quote_url = self.event.data["url"]
            single_quote = await http_compare.compare(single_quote_url, cookies=cookies)
        else:
            single_quote_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}'"
            single_quote = await http_compare.compare(single_quote_url)
        self.parent.hugeinfo("Single Quote URL")
        self.parent.hugewarning(single_quote_url)
        self.parent.critical(single_quote)

        # Add Two Single Quotes
        if self.event.data["type"] == "COOKIE":
            cookies = {self.event.data["name"]: f"{self.event.data['original_value']}''"}
            double_single_quote_url = self.event.data["url"]
            double_single_quote = await http_compare.compare(double_single_quote_url, cookies=cookies)
        else:
            double_single_quote_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}''"
            double_single_quote = await http_compare.compare(double_single_quote_url)
        self.parent.hugeinfo("Double Single Quote URL")
        self.parent.hugewarning(double_single_quote_url)

        self.parent.critical(double_single_quote)
        # send error probe

        if "code" in single_quote[1] and "code" not in double_single_quote[1]:
            self.results.append(
                f"Possible SQL Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Single Quote/Two Single Quote]"
            )

        #

        # send diff probe

        # send delay probe


class XSSLightfuzz(BaseLightfuzz):
    def determine_context(self, html, random_string):
        between_tags = False
        in_tag_attribute = False
        in_javascript = False

        between_tags_regex = re.compile(rf"<(\/?\w+)[^>]*>.*?{random_string}.*?<\/?\w+>")
        in_tag_attribute_regex = re.compile(rf'<(\w+)\s+[^>]*?(\w+)="([^"]*?{random_string}[^"]*?)"[^>]*>')
        in_javascript_regex = re.compile(
            rf"<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?{random_string}(?:(?!<\/script>)[\s\S])*?<\/script>"
        )

        between_tags_match = re.search(between_tags_regex, html)
        if between_tags_match:
            between_tags = True

        in_tag_attribute_match = re.search(in_tag_attribute_regex, html)
        if in_tag_attribute_match:
            in_tag_attribute = True

        in_javascript_regex = re.search(in_javascript_regex, html)
        if in_javascript_regex:
            in_javascript = True

        return between_tags, in_tag_attribute, in_javascript

    async def fuzz(self):
        parent_event = self.event.source

        # If this came from paramminer_getparams and didn't have a http_reflection tag, we don't need to check again
        if (
            parent_event.type == "WEB_PARAMETER"
            and parent_event.source.type == "paramminer_getparams"
            and "http_reflection" not in parent_event.tags
        ):
            return

        reflection = None

        random_string = self.parent.helpers.rand_string(8)
        reflection_probe_result = await self.send_probe(random_string)
        if reflection_probe_result and random_string in reflection_probe_result:
            reflection = True

        if not reflection or reflection == False:
            return

        between_tags, in_tag_attribute, in_javascript = self.determine_context(reflection_probe_result, random_string)

        self.parent.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )

        if between_tags:
            between_tags_probe = f"<b>{random_string}</b>"
            probe_result = await self.send_probe(between_tags_probe)
            if probe_result:
                if between_tags_probe in probe_result:
                    self.results.append(
                        f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [Between Tags]"
                    )

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"'
            in_tag_attribute_match = f'"{random_string}""'
            probe_result = await self.send_probe(in_tag_attribute_probe)
            if probe_result:
                if in_tag_attribute_match in probe_result:
                    self.results.append(
                        f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [Tab Attribute]"
                    )

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            probe_result = await self.send_probe(in_javascript_probe)
            if probe_result:
                if in_javascript_probe in probe_result:
                    self.results.append(
                        f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [In Javascript]"
                    )


class lightfuzz(BaseModule):
    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "web-thorough"]
    meta = {"description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner"}

    def _outgoing_dedup_hash(self, event):
        return hash(
            (
                "lightfuzz",
                str(event.host),
                event.data["url"],
                event.data["description"],
                event.data.get("type", ""),
                event.data.get("name", ""),
            )
        )

    async def handle_event(self, event):
        if event.type == "HTTP_RESPONSE":
            headers = event.data.get("header", "")
            for k, v in headers.items():
                if k == "set_cookie":
                    if "=" not in v:
                        self.critical(f"DEBUG FOR COOKIE WITHOUT =: {v}")
                    else:
                        cookie_name = v.split("=")[0]
                        cookie_value = v.split("=")[1].split(";")[0]
                        description = f"Set-Cookie Assigned Cookie [{cookie_name}]"
                        data = {
                            "host": str(event.host),
                            "type": "COOKIE",
                            "name": cookie_name,
                            "original_value": cookie_value,
                            "url": event.data["url"],
                            "description": description,
                        }
                        self.emit_event(data, "WEB_PARAMETER", event)

            # self.hugeinfo(k)

            # self.critical(v)
            return
            body = event.data.get("body", "")

            for endpoint, parameter_name, original_value, regex_name in extract_params_html(body):
                if endpoint == None:
                    endpoint = "/"

                if endpoint.startswith("http://") or endpoint.startswith("https://"):
                    url = endpoint
                else:
                    url = f"{str(event.data['scheme'])}://{str(event.host)}{endpoint}"

                self.debug(
                    f"extract_params_html returned: endpoint [{endpoint}], parameter_name [{parameter_name}], regex_name [{regex_name}]"
                )

                description = f"HTTP Extracted Parameter [{parameter_name}]"
                data = {
                    "host": str(event.host),
                    "type": "GETPARAM",
                    "name": parameter_name,
                    "original_value": original_value,
                    "url": url,
                    "description": description,
                    "regex_name": regex_name,
                }
                self.emit_event(data, "WEB_PARAMETER", event)

        elif event.type == "WEB_PARAMETER":
            if event.data["type"] == "GETPARAM":
                pass
                # XSS
                self.hugeinfo("STARTING XSS FUZZ")
                xsslf = XSSLightfuzz(self, event)
                await xsslf.fuzz()
                if len(xsslf.results) > 0:
                    for r in xsslf.results:
                        self.emit_event(
                            {"host": str(event.host), "url": event.data["url"], "description": r},
                            "FINDING",
                            event,
                        )

            # SQLI
            self.hugeinfo("STARTING SQLI FUZZ")
            sqlilf = SQLiLightfuzz(self, event)
            await sqlilf.fuzz()
            if len(sqlilf.results) > 0:
                for r in sqlilf.results:
                    self.emit_event(
                        {"host": str(event.host), "url": event.data["url"], "description": r},
                        "FINDING",
                        event,
                    )

        # Add extractor for cookies (via set-cookie, or eventually javascript code) and eventually headers (probably just via JS)
