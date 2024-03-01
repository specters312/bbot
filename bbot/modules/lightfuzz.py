# adapted from https://github.com/bugcrowd/HUNT

from bbot.modules.base import BaseModule
import statistics
import re
import urllib.parse

from bbot.core.helpers.misc import extract_params_html
from bbot.core.errors import InteractshError


class BaseLightfuzz:
    def __init__(self, lightfuzz, event):
        self.lightfuzz = lightfuzz
        self.event = event
        self.results = []

    async def send_probe(self, probe):
        getparams = {self.event.data["name"]: probe}
        url = self.lightfuzz.helpers.add_get_params(self.event.data["url"], getparams).geturl()

        self.lightfuzz.debug(f"lightfuzz sending probe with URL: {url}")

        r = await self.lightfuzz.helpers.request(method="GET", url=url, allow_redirects=False, retries=2, timeout=10)
        if r:
            return r.text


class CmdILightFuzz(BaseLightfuzz):
    async def fuzz(self):

        cookies = self.event.data.get("assigned_cookies", {})
        if (
            "original_value" in self.event.data
            and self.event.data["original_value"] is not None
            and len(self.event.data["original_value"]) != 0
        ):
            probe_value = self.event.data["original_value"]
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        canary = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        if self.event.data["type"] == "GETPARAM":
            query_string = f"{self.event.data['name']}={probe_value}"
            baseline_url = f"{self.event.data['url']}?{query_string}"
        else:
            baseline_url = self.event.data["url"]

        if self.event.data["type"] == "GETPARAM":
            http_compare = self.lightfuzz.helpers.http_compare(baseline_url, include_cache_buster=False, timeout=15)

        elif self.event.data["type"] == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe_value}
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, include_cache_buster=False, cookies={**cookies, **cookies_probe}, timeout=15
            )
        elif self.event.data["type"] == "HEADER":
            headers = {self.event.data["name"]: probe_value}
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, include_cache_buster=False, headers=headers, timeout=15
            )
        elif self.event.data["type"] == "POSTPARAM":
            data = {self.event.data["name"]: probe_value}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, include_cache_buster=False, data=data, method="POST", timeout=15
            )

        cmdi_probe_strings = [
            ";",
            "&&",
            "||",
            "&",
            "|",
            "MMMM",
        ]

        positive_detections = []
        for p in cmdi_probe_strings:
            probe = f"{p} echo {canary} {p}"
            if self.event.data["type"] == "COOKIE":
                cookies_probe = {self.event.data["name"]: f"{probe_value}{probe}"}
                probe_url = self.event.data["url"]
                cmdi_probe = await http_compare.compare(probe_url, cookies={**cookies, **cookies_probe}, timeout=30)
            elif self.event.data["type"] == "GETPARAM":
                encoded_probe_value = urllib.parse.quote(f"{probe_value}{probe}".encode())
                probe_url = f"{self.event.data['url']}?{self.event.data['name']}={encoded_probe_value}"
                cmdi_probe = await http_compare.compare(probe_url, timeout=30)
            elif self.event.data["type"] == "HEADER":
                headers = {self.event.data["name"]: f"{probe_value}{probe}"}
                probe_url = self.event.data["url"]
                cmdi_probe = await http_compare.compare(probe_url, headers=headers, timeout=30)
            elif self.event.data["type"] == "POSTPARAM":
                data = {self.event.data["name"]: f"{probe_value}{probe}"}
                if self.event.data["additional_params"] is not None:
                    data.update(self.event.data["additional_params"])
                probe_url = self.event.data["url"]
                cmdi_probe = await http_compare.compare(probe_url, timeout=30, method="POST", data=data)
            else:
                self.lightfuzz.debug(f'Got unexpected value for self.event.data["type"]: [{self.event.data["type"]}]')
                break

            if cmdi_probe[3]:
                if canary in cmdi_probe[3].text and "echo" not in cmdi_probe[3].text:
                    self.lightfuzz.debug(f"canary [{canary}] found in response when sending probe [{p}]")
                    positive_detections.append(p)
        if len(positive_detections) > 0:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"POSSIBLE OS Command Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [echo canary] CMD Probe Delimeters: [{' '.join(positive_detections)}]",
                }
            )

        # Blind OS Command Injection
        if self.lightfuzz.interactsh_instance:
            self.lightfuzz.event_dict[self.event.data["url"]] = self.event

            for p in cmdi_probe_strings:

                subdomain_tag = self.lightfuzz.helpers.rand_string(4, digits=False)
                self.lightfuzz.interactsh_subdomain_tags[subdomain_tag] = {
                    "event": self.event,
                    "type": self.event.data["type"],
                    "name": self.event.data["name"],
                    "probe": p,
                }
                probe = f"{p} nslookup {subdomain_tag}.{self.lightfuzz.interactsh_domain} {p}"
                if self.event.data["type"] == "COOKIE":
                    cookies_probe = {self.event.data["name"]: f"{probe_value}{probe}"}
                    probe_url = self.event.data["url"]
                    await self.lightfuzz.helpers.request(
                        method="GET",
                        url=probe_url,
                        allow_redirects=False,
                        cookies={**cookies, **cookies_probe},
                        timeout=15,
                    )
                elif self.event.data["type"] == "GETPARAM":
                    encoded_probe_value = urllib.parse.quote(f"{probe_value}{probe}".encode())
                    probe_url = f"{self.event.data['url']}?{self.event.data['name']}={encoded_probe_value}"
                    await self.lightfuzz.helpers.request(
                        method="GET", url=probe_url, allow_redirects=False, timeout=15
                    )
                elif self.event.data["type"] == "HEADER":
                    headers = {self.event.data["name"]: f"{probe_value}{probe}"}
                    probe_url = self.event.data["url"]
                    await self.lightfuzz.helpers.request(
                        method="GET", url=probe_url, allow_redirects=False, headers=headers, timeout=15
                    )
                elif self.event.data["type"] == "POSTPARAM":
                    data = {self.event.data["name"]: f"{probe_value}{probe}"}
                    if self.event.data["additional_params"] is not None:
                        data.update(self.event.data["additional_params"])
                    probe_url = self.event.data["url"]
                    await self.lightfuzz.helpers.request(
                        method="POST", url=probe_url, allow_redirects=False, data=data, timeout=15
                    )
        else:
            self.lightfuzz.debug(
                "Aborting Blind Command Injection check due to interactsh global disable or interactsh setup failure"
            )
            return None


class SQLiLightfuzz(BaseLightfuzz):
    expected_delay = 5

    def evaluate_delay(self, mean_baseline, measured_delay):
        margin = 1
        if (
            mean_baseline + self.expected_delay - margin
            <= measured_delay
            <= mean_baseline + self.expected_delay + margin
        ):
            return True
        # check for exactly twice the delay, in case the statement gets placed in the query twice
        elif (
            mean_baseline + (self.expected_delay * 2) - margin
            <= measured_delay
            <= mean_baseline + (self.expected_delay * 2) + margin
        ):
            return True
        else:
            return False

    async def fuzz(self):

        if "original_value" in self.event.data and self.event.data["original_value"] is not None:
            probe_value = self.event.data["original_value"]
        else:
            probe_value = self.lightfuzz.helpers.rand_string(8, numeric_only=True)

        if self.event.data["type"] == "GETPARAM":
            baseline_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}"
        else:
            baseline_url = self.event.data["url"]

        cookies = self.event.data.get("assigned_cookies", {})

        if self.event.data["type"] == "GETPARAM":
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, cookies=cookies, include_cache_buster=False
            )
        elif self.event.data["type"] == "COOKIE":
            cookies_probe = {self.event.data["name"]: f"{self.event.data['original_value']}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, include_cache_buster=False, cookies={**cookies, **cookies_probe}
            )
        elif self.event.data["type"] == "HEADER":
            headers = {self.event.data["name"]: f"{self.event.data['original_value']}"}
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, include_cache_buster=False, headers=headers, cookies=cookies
            )
        elif self.event.data["type"] == "POSTPARAM":
            data = {self.event.data["name"]: f"{self.event.data['original_value']}"}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            http_compare = self.lightfuzz.helpers.http_compare(
                baseline_url, method="POST", include_cache_buster=False, data=data, cookies=cookies
            )

        # Add Single Quote
        if self.event.data["type"] == "COOKIE":
            cookies_probe = {self.event.data["name"]: f"{probe_value}'"}
            single_quote_url = self.event.data["url"]
            single_quote = await http_compare.compare(single_quote_url, cookies={**cookies, **cookies_probe})
        elif self.event.data["type"] == "GETPARAM":
            single_quote_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}'"
            single_quote = await http_compare.compare(single_quote_url, cookies=cookies)
        elif self.event.data["type"] == "HEADER":
            headers = {self.event.data["name"]: f"{probe_value}'"}
            single_quote_url = self.event.data["url"]
            single_quote = await http_compare.compare(single_quote_url, headers=headers, cookies=cookies)
        elif self.event.data["type"] == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe_value}'"}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            single_quote_url = self.event.data["url"]
            single_quote = await http_compare.compare(single_quote_url, method="POST", data=data, cookies=cookies)

        # Add Two Single Quotes
        if self.event.data["type"] == "COOKIE":
            cookies_probe = {self.event.data["name"]: f"{probe_value}''"}
            double_single_quote_url = self.event.data["url"]
            double_single_quote = await http_compare.compare(
                double_single_quote_url, cookies={**cookies, **cookies_probe}
            )
        elif self.event.data["type"] == "GETPARAM":
            double_single_quote_url = f"{self.event.data['url']}?{self.event.data['name']}={probe_value}''"
            double_single_quote = await http_compare.compare(double_single_quote_url, cookies=cookies)
        elif self.event.data["type"] == "HEADER":
            headers = {self.event.data["name"]: f"{probe_value}''"}
            double_single_quote_url = self.event.data["url"]
            double_single_quote = await http_compare.compare(double_single_quote_url, headers=headers, cookies=cookies)
        elif self.event.data["type"] == "POSTPARAM":
            data = {self.event.data["name"]: f"{probe_value}''"}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            double_single_quote_url = self.event.data["url"]
            double_single_quote = await http_compare.compare(
                double_single_quote_url, method="POST", data=data, cookies=cookies
            )

        if "code" in single_quote[1] and "code" not in double_single_quote[1]:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": f"Possible SQL Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Single Quote/Two Single Quote]",
                }
            )

        delay_probe_strings = [
            f"'||pg_sleep({str(self.expected_delay)})--",  # postgres
            f"1' AND (SLEEP({str(self.expected_delay)})) AND '",  # mysql
            f"' AND (SELECT FROM DBMS_LOCK.SLEEP({str(self.expected_delay)})) AND '1'='1"  # oracle (not tested)
            f"; WAITFOR DELAY '00:00:{str(self.expected_delay)}'--",  # mssql (not tested)
        ]
        method = "GET"

        if self.event.data["type"] == "COOKIE":
            cookies_probe = {self.event.data["name"]: probe_value}
            baseline_1 = await self.lightfuzz.helpers.request(
                method=method,
                cookies={**cookies, **cookies_probe},
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
            baseline_2 = await self.lightfuzz.helpers.request(
                method=method,
                cookies={**cookies, **cookies_probe},
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
        elif self.event.data["type"] == "GETPARAM":
            baseline_1 = await self.lightfuzz.helpers.request(
                method=method,
                cookies=cookies,
                url=f"{self.event.data['url']}?{self.event.data['name']}={probe_value}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
            baseline_2 = await self.lightfuzz.helpers.request(
                method=method,
                cookies=cookies,
                url=f"{self.event.data['url']}?{self.event.data['name']}={probe_value}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
        elif self.event.data["type"] == "HEADER":
            headers = {self.event.data["name"]: probe_value}
            baseline_1 = await self.lightfuzz.helpers.request(
                method=method,
                cookies=cookies,
                headers=headers,
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
            baseline_2 = await self.lightfuzz.helpers.request(
                method=method,
                cookies=cookies,
                headers=headers,
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )

        elif self.event.data["type"] == "POSTPARAM":
            data = {self.event.data["name"]: probe_value}
            if self.event.data["additional_params"] is not None:
                data.update(self.event.data["additional_params"])
            baseline_1 = await self.lightfuzz.helpers.request(
                method="POST",
                data=data,
                cookies=cookies,
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )
            baseline_2 = await self.lightfuzz.helpers.request(
                method="POST",
                data=data,
                cookies=cookies,
                url=f"{self.event.data['url']}",
                allow_redirects=False,
                retries=0,
                timeout=10,
            )

        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            mean_baseline = statistics.mean([baseline_1_delay, baseline_2_delay])

            for p in delay_probe_strings:
                if self.event.data["type"] == "COOKIE":
                    cookies_probe = {self.event.data["name"]: f"{probe_value}{p}"}
                    r = await self.lightfuzz.helpers.request(
                        method=method,
                        cookies={**cookies, **cookies_probe},
                        url=f"{self.event.data['url']}",
                        allow_redirects=False,
                        retries=0,
                        timeout=60,
                    )
                elif self.event.data["type"] == "GETPARAM":
                    r = await self.lightfuzz.helpers.request(
                        method=method,
                        cookies=cookies,
                        url=f"{self.event.data['url']}?{self.event.data['name']}={probe_value}{p}",
                        allow_redirects=False,
                        retries=0,
                        timeout=60,
                    )

                elif self.event.data["type"] == "HEADER":
                    headers = {self.event.data["name"]: f"{probe_value}{p}"}
                    r = await self.lightfuzz.helpers.request(
                        method=method,
                        headers=headers,
                        cookies=cookies,
                        url=f"{self.event.data['url']}",
                        allow_redirects=False,
                        retries=0,
                        timeout=60,
                    )

                elif self.event.data["type"] == "POSTPARAM":
                    data = {self.event.data["name"]: f"{probe_value}{p}"}
                    if self.event.data["additional_params"] is not None:
                        data.update(self.event.data["additional_params"])
                    r = await self.lightfuzz.helpers.request(
                        method="POST",
                        data=data,
                        cookies=cookies,
                        url=f"{self.event.data['url']}",
                        allow_redirects=False,
                        retries=0,
                        timeout=60,
                    )

                if not r:
                    self.lightfuzz.debug("delay measure request failed")
                    continue
                d = r.elapsed.total_seconds()
                self.lightfuzz.debug(f"measured delay: {str(d)}")
                if self.evaluate_delay(mean_baseline, d):
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Blind SQL Injection. Parameter: [{self.event.data['name']}] Parameter Type: [{self.event.data['type']}] Detection Method: [Delay Probe ({p})]",
                        }
                    )
                else:
                    self.lightfuzz.debug("Error obtaining delay")
        else:
            self.lightfuzz.debug("Could not get baseline for time-delay tests")


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
        lightfuzz_event = self.event.source

        # If this came from paramminer_getparams and didn't have a http_reflection tag, we don't need to check again
        if (
            lightfuzz_event.type == "WEB_PARAMETER"
            and lightfuzz_event.source.type == "paramminer_getparams"
            and "http_reflection" not in lightfuzz_event.tags
        ):
            return

        reflection = None

        random_string = self.lightfuzz.helpers.rand_string(8)
        reflection_probe_result = await self.send_probe(random_string)
        if reflection_probe_result and random_string in reflection_probe_result:
            reflection = True

        if not reflection or reflection == False:
            return

        between_tags, in_tag_attribute, in_javascript = self.determine_context(reflection_probe_result, random_string)

        self.lightfuzz.debug(
            f"determine_context returned: between_tags [{between_tags}], in_tag_attribute [{in_tag_attribute}], in_javascript [{in_javascript}]"
        )

        if between_tags:
            between_tags_probe = f"<z>{random_string}</z>"
            probe_result = await self.send_probe(between_tags_probe)
            if probe_result:
                if between_tags_probe in probe_result:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [Between Tags]",
                        }
                    )

        if in_tag_attribute:
            in_tag_attribute_probe = f'{random_string}"'
            in_tag_attribute_match = f'"{random_string}""'
            probe_result = await self.send_probe(in_tag_attribute_probe)
            if probe_result:
                if in_tag_attribute_match in probe_result:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [Tab Attribute]",
                        }
                    )

        if in_javascript:
            in_javascript_probe = rf"</script><script>{random_string}</script>"
            probe_result = await self.send_probe(in_javascript_probe)
            if probe_result:
                if in_javascript_probe in probe_result:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": f"Possible Reflected XSS. Parameter: [{self.event.data['name']}] Context: [In Javascript]",
                        }
                    )


class lightfuzz(BaseModule):
    watched_events = ["URL", "HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "web-thorough"]
    options = {"force_common_headers": False, "submodule_sqli": True, "submodule_xss": True, "submodule_cmdi": True}
    options_desc = {
        "force_common_headers": "Force emit commonly exploitable parameters that may be difficult to detect",
        "submodule_sqli": "Enable the SQL Injection Submodule",
        "submodule_xss": "Enable the XSS Submodule",
        "submodule_cmdi": "Enable the Command Injection Submodule",
    }
    meta = {"description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner"}
    common_headers = ["x-forwarded-for", "user-agent"]
    parameter_blacklist = ["__VIEWSTATE", "__EVENTARGUMENT", "JSESSIONID"]
    in_scope_only = True

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None

        self.submodule_sqli = False
        self.submodule_cmdi = False
        self.submodule_xss = False

        if self.config.get("submodule_sqli", False) == True:
            self.submodule_sqli = True
            self.hugeinfo("Lightfuzz SQL Injection Submodule Enabled")

        if self.config.get("submodule_xss", False) == True:
            self.submodule_xss = True
            self.hugeinfo("Lightfuzz XSS Submodule Enabled")

        if self.config.get("submodule_cmdi", False) == True:
            self.submodule_cmdi = True
            self.hugeinfo("Lightfuzz Command Injection Submodule Enabled")

            if self.scan.config.get("interactsh_disable", False) == False:

                try:
                    self.interactsh_instance = self.helpers.interactsh()
                    self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
                except InteractshError as e:
                    self.warning(f"Interactsh failure: {e}")

        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                details = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not details["event"]:
                    return
                await self.emit_event(
                    {
                        "severity": "CRITICAL",
                        "host": str(details["event"].host),
                        "url": details["event"].data["url"],
                        "description": f"OS Command Injection (OOB Interaction) Type: [{details['type']}] Parameter Name: [{details['name']}] Probe: [{details['probe']}]",
                    },
                    "VULNERABILITY",
                    details["event"],
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

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
        if event.type == "URL":
            if self.config.get("force_common_headers", False) == False:

                return False

            for h in self.common_headers:
                description = f"Speculative (Forced) Header [{h}]"
                data = {
                    "host": str(event.host),
                    "type": "HEADER",
                    "name": h,
                    "original_value": None,
                    "url": event.data,
                    "description": description,
                }
                await self.emit_event(data, "WEB_PARAMETER", event)

        if event.type == "HTTP_RESPONSE":
            assigned_cookies = {}

            headers = event.data.get("header", "")
            for k, v in headers.items():
                if k == "set_cookie":

                    if "=" not in v:
                        self.critical(f"DEBUG FOR COOKIE WITHOUT =: {v}")
                    else:

                        in_bl = False
                        for bl_param in self.parameter_blacklist:
                            if bl_param.lower() == k.lower():
                                in_bl = True
                                continue

                        if in_bl == False:
                            cookie_name = v.split("=")[0]
                            cookie_value = v.split("=")[1].split(";")[0]

                            assigned_cookies[cookie_name] = cookie_value

                            description = f"Set-Cookie Assigned Cookie [{cookie_name}]"
                            data = {
                                "host": str(event.host),
                                "type": "COOKIE",
                                "name": cookie_name,
                                "original_value": cookie_value,
                                "url": event.data["url"],
                                "description": description,
                            }
                            await self.emit_event(data, "WEB_PARAMETER", event)

            body = event.data.get("body", "")

            for method, endpoint, parameter_name, original_value, regex_name, additional_params in extract_params_html(
                body
            ):
                in_bl = False

                if endpoint == None or endpoint == "":
                    endpoint = event.data["url"]

                if endpoint.startswith("http://") or endpoint.startswith("https://"):
                    url = endpoint
                else:
                    url = f"{str(event.data['scheme'])}://{str(event.host)}{endpoint}"

                self.debug(
                    f"extract_params_html returned: endpoint [{endpoint}], parameter_name [{parameter_name}], regex_name [{regex_name}]"
                )

                if method == None or method == "GET":
                    paramtype = "GETPARAM"
                elif method == "POST":
                    paramtype = "POSTPARAM"
                else:
                    self.warning(f"Invalid method received! ({method})")
                    continue

                for bl_param in self.parameter_blacklist:
                    if parameter_name.lower() == bl_param:
                        in_bl = True
                        continue

                if in_bl == False:
                    description = f"HTTP Extracted Parameter [{parameter_name}]"
                    data = {
                        "host": str(event.host),
                        "type": paramtype,
                        "name": parameter_name,
                        "original_value": original_value,
                        "url": url,
                        "description": description,
                        "additional_params": additional_params,
                        "assigned_cookies": assigned_cookies,
                        "regex_name": regex_name,
                    }
                    await self.emit_event(data, "WEB_PARAMETER", event)

        elif event.type == "WEB_PARAMETER":

            if self.submodule_xss:
                if event.data["type"] == "GETPARAM":
                    self.debug("STARTING XSS FUZZ")
                    xsslf = XSSLightfuzz(self, event)
                    await xsslf.fuzz()
                    if len(xsslf.results) > 0:
                        for r in xsslf.results:
                            await self.emit_event(
                                {"host": str(event.host), "url": event.data["url"], "description": r["description"]},
                                "FINDING",
                                event,
                            )

            if self.submodule_sqli:
                self.debug("STARTING SQLI FUZZ")
                sqlilf = SQLiLightfuzz(self, event)
                await sqlilf.fuzz()
                if len(sqlilf.results) > 0:
                    for r in sqlilf.results:
                        await self.emit_event(
                            {"host": str(event.host), "url": event.data["url"], "description": r["description"]},
                            "FINDING",
                            event,
                        )

            if self.submodule_cmdi:

                self.debug("Starting CMDI FUZZ")

                cmdilf = CmdILightFuzz(self, event)
                await cmdilf.fuzz()
                if len(cmdilf.results) > 0:
                    for r in cmdilf.results:
                        if r["type"] == "FINDING":
                            await self.emit_event(
                                {"host": str(event.host), "url": event.data["url"], "description": r["description"]},
                                "FINDING",
                                event,
                            )
                        elif r["type"] == "VULNERABILITY":
                            await self.emit_event(
                                {
                                    "host": str(event.host),
                                    "url": event.data["url"],
                                    "description": r["description"],
                                    "severity": r["severity"],
                                },
                                "VULNERABILITY",
                                event,
                            )

    async def filter_event(self, event):
        if "in-scope" not in event.tags:
            return False
        return True

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
