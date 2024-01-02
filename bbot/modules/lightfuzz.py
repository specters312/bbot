# adapted from https://github.com/bugcrowd/HUNT

from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import extract_params_html

class BaseLightfuzz:
    def __init__(self, parameter_event):
        self.parameter_event = parameter_event


class XSSLightfuzz(BaseLightfuzz):

    def fuzz(self):

        self.critical("FUZZ CODE HERE")
        self.critical(self.parameter_event.parent)

class lightfuzz(BaseModule):
    watched_events = ["HTTP_RESPONSE","WEB_PARAMETER"]
    produced_events = ["FINDING","VULNERABILITY"]
    flags = ["active", "web-thorough"]
    meta = {"description": "Find Web Parameters and Lightly Fuzz them using a heuristic based scanner"}

    async def handle_event(self, event):

        if event.type == "HTTP_RESPONSE":
            body = event.data.get("body", "")


            # this will completely change when we account for FULL URL. we will have to make a conditional where we pass back the domain, if we find one, and if we dont only then will we pass this one on.

            for endpoint,parameter_name in extract_params_html(body):
                url = f"{str(event.data['scheme'])}://{str(event.host)}{endpoint}"

                data = {"host": str(event.host), "type":"GETPARAM","name": parameter_name, "url":url}
                self.emit_event(data, "WEB_PARAMETER", event)
                

        elif event.type == "WEB_PARAMETER":
            self.critical("GOT WEB PARAMETER")
            xsslf = XSSLightfuzz(event)
            self.critical(lf.parameter_event.url)
            self.critical(lf.parameter_event.name)

        # Add extractor for cookies (via set-cookie, or eventually javascript code) and eventually headers (probably just via JS)