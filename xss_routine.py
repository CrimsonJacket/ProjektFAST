#!/usr/bin/python
import random
import re
import string
import logging
import urllib.error
import urllib.error
import urllib.parse
import urllib.parse
import urllib.parse
import urllib.request
import urllib.request


class XssRoutine:

    def __init__(self):
        self.LOGGER = logging.getLogger(__name__)
        self.LOGGER.setLevel(logging.INFO)

        # create a file handler
        handler = logging.FileHandler('FAST.log')
        handler.setLevel(logging.INFO)

        # create a logging format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # add the handlers to the self.LOGGER
        self.LOGGER.addHandler(handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.LOGGER.addHandler(stream_handler)

    _headers = {}

    TIMEOUT = 30

    # filtering regex used before DOM XSS search
    DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"

    # each (dom pattern) item consists of r"recognition regex"
    DOM_PATTERNS = (
        r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
        r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>"
    )

    # enumerator-like values used for marking current phase
    GET, POST = "GET", "POST"

    # length of random prefix/suffix used in XSS tampering
    PREFIX_SUFFIX_LENGTH = 5

    # characters used for XSS tampering of parameter values (larger set)
    LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')

    # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
    SMALLER_CHAR_POOL = ('<', '>')

    # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    REGULAR_PATTERNS = (
        (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'"),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"'),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
    )

    def _retrieve_content(self, url, data=None):
        try:
            req = urllib.request.Request(
                "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url))), data,
                XssRoutine._headers)
            retval = urllib.request.urlopen(req, timeout=XssRoutine.TIMEOUT).read()
        except Exception as ex:
            retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
        return str(retval) or ""

    def _contains(self, content, chars):
        content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
        return all(char in content for char in chars)

    def scan_page(self, url, data=None):
        retval, usable = False, False
        url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>",data) if data else data
        original = re.sub(XssRoutine.DOM_FILTER_REGEX, "", self._retrieve_content(url, data))
        vulnerable_parameter = ""
        # dom = max(re.search(abc, original) for abc in DOM_PATTERNS)
        # Fix code start
        temp = []
        for dom_regex in XssRoutine.DOM_PATTERNS:
            blah = re.search(dom_regex, original)
            if blah:
                temp.append(blah)

        if temp:
            dom = max(temp)
        else:
            dom = ''
        # Fix code end

        if dom:
            self.LOGGER.info(" (i) page itself appears to be XSS vulnerable (DOM)")
            self.LOGGER.info("  (o) ...%s..." % dom.group(0))
            retval = True
        try:
            for phase in (XssRoutine.GET, XssRoutine.POST):
                current = url if phase is XssRoutine.GET else (data or "")
                for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                    found, usable = False, True
                    # print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                    prefix, suffix = ("".join(random.sample(string.ascii_lowercase, XssRoutine.PREFIX_SUFFIX_LENGTH)) for
                                      i in range(2))
                    for pool in (XssRoutine.LARGER_CHAR_POOL, XssRoutine.SMALLER_CHAR_POOL):
                        if not found:
                            tampered = current.replace(
                                match.group(0),
                                "%s%s" % (
                                    match.group(0),
                                    urllib.parse.quote("%s%s%s%s" % (
                                    "'" if pool == XssRoutine.LARGER_CHAR_POOL else "", prefix,
                                    "".join(random.sample(pool, len(pool))), suffix))
                                )
                            )
                            content = (
                                self._retrieve_content(tampered, data) if phase is XssRoutine.GET else self._retrieve_content(url,
                                                                                                                   tampered)).replace(
                                "%s%s" % ("'" if pool == XssRoutine.LARGER_CHAR_POOL else "", prefix), prefix)
                            for regex, condition, info, content_removal_regex in XssRoutine.REGULAR_PATTERNS:
                                filtered = re.sub(content_removal_regex or "", "", content)
                                for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):
                                    context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                    if context and not found and sample.group(1).strip():
                                        if self._contains(sample.group(1), condition):
                                            # print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                            found = retval = True
                                            vulnerable_parameter = match.group("parameter")
                                        break
            if not usable:
                self.LOGGER.info(" (x) no usable GET/POST parameters found")
        except KeyboardInterrupt:
            self.LOGGER.info("\r (x) Ctrl-C pressed")
        return retval, vulnerable_parameter
    # End of referenced code

    def scan_url_list(self):
        for url in self.URL_LIST:
            self.LOGGER.info("[-] Scanning: " + url)
            scan_result = self.scan_page(url)
            if scan_result[0]:
                self.LOGGER.info("[+] Potential vulnerable URL: " + url + " @" + scan_result[1])
                XssRoutine.VUL_URL.append((url, scan_result[1]))

        self.LOGGER.info(XssRoutine.VUL_URL)
