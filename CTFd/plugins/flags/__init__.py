import re
import base64
import subprocess
import tempfile
import os
import json

from CTFd.plugins import register_plugin_assets_directory


class FlagException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class BaseFlag(object):
    name = None
    templates = {}

    @staticmethod
    def compare(self, saved, provided):
        return True


class CTFdStaticFlag(BaseFlag):
    name = "static"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/flags/assets/secret/create.html",
        "update": "/plugins/flags/assets/secret/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        saved = chal_key_obj.content
        data = chal_key_obj.data

        if len(saved) != len(provided):
            return False
        result = 0

        if data == "case_insensitive":
            for x, y in zip(saved.lower(), provided.lower()):
                result |= ord(x) ^ ord(y)
        else:
            for x, y in zip(saved, provided):
                result |= ord(x) ^ ord(y)
        return result == 0


class CTFdRegexFlag(BaseFlag):
    name = "regex"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/flags/assets/regex/create.html",
        "update": "/plugins/flags/assets/regex/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        saved = chal_key_obj.content
        data = chal_key_obj.data

        try:
            if data == "case_insensitive":
                res = re.match(saved, provided, re.IGNORECASE)
            else:
                res = re.match(saved, provided)
        # TODO: this needs plugin improvements. See #1425.
        except re.error as e:
            raise FlagException("Regex parse error occured") from e

        return res and res.group() == provided

class CTFdJqFlag(BaseFlag):
    name = "jq"
    templates = {
        "create": "/plugins/flags/assets/jq/create.html",
        "update": "/plugins/flags/assets/jq/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        saved = chal_key_obj.content

        try:
            with tempfile.NamedTemporaryFile() as tmp:
                subprocess.call(["jq", "-s", provided, os.path.join('/opt/CTFd/etc/json', chal_key_obj.data)], stdout=tmp)
                tmp.seek(0)
                provided = tmp.read()
                tmp.close()
                pj = json.loads(provided)
                sj = json.loads(saved)
                return pj == sj
        except e:
            raise FlagException("Regex parse error occured") from e
        raise False

class CTFdSecretFlag(BaseFlag):
    name = "secret"
    templates = {
        "create": "/plugins/flags/assets/static/create.html",
        "update": "/plugins/flags/assets/static/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        saved = chal_key_obj.content

        try:
            with tempfile.NamedTemporaryFile() as tmp:
                if len(saved) >= len(provided):
                    return False
                if saved != provided[:len(saved)]:
                    return False
                subprocess.call(["jq", 'select(.event_type=="alert") | .http.url', '/var/log/suricata/eve.json'], stdout=tmp)
                tmp.seek(0)
                for l in tmp.readlines():
                    if "/secret="+provided in l.decode("utf-8"):
                        return True
                tmp.close()
                return False
        except e:
            raise FlagException("Secret error occured") from e
        raise False

FLAG_CLASSES = {"static": CTFdStaticFlag, "regex": CTFdRegexFlag, "jq": CTFdJqFlag, "secret": CTFdSecretFlag}


def get_flag_class(class_id):
    cls = FLAG_CLASSES.get(class_id)
    if cls is None:
        raise KeyError
    return cls


def load(app):
    register_plugin_assets_directory(app, base_path="/plugins/flags/assets/")
