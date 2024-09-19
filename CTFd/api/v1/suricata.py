from typing import List  # noqa: I001

from flask import abort, render_template, request, url_for
from flask_restx import Namespace, Resource
from sqlalchemy.sql import and_

from CTFd.api.v1.helpers.request import validate_args
from CTFd.api.v1.helpers.schemas import sqlalchemy_to_pydantic
from CTFd.api.v1.schemas import APIDetailedSuccessResponse, APIListSuccessResponse
from CTFd.cache import clear_challenges, clear_standings
from CTFd.constants import RawEnum
from CTFd.models import ChallengeFiles as ChallengeFilesModel
from CTFd.models import Challenges
from CTFd.models import ChallengeTopics as ChallengeTopicsModel
from CTFd.models import Fails, Flags, Hints, HintUnlocks, Solves, Submissions, Tags, db
from CTFd.plugins.challenges import CHALLENGE_CLASSES, get_chal_class
from CTFd.schemas.challenges import ChallengeSchema
from CTFd.schemas.flags import FlagSchema
from CTFd.schemas.hints import HintSchema
from CTFd.schemas.tags import TagSchema
from CTFd.utils import config, get_config
from CTFd.utils import user as current_user
from CTFd.utils.challenges import (
    get_all_challenges,
    get_solve_counts_for_challenges,
    get_solve_ids_for_user_id,
    get_solves_for_challenge_id,
)
from CTFd.utils.config.visibility import (
    accounts_visible,
    challenges_visible,
    scores_visible,
)
from CTFd.utils.dates import ctf_ended, ctf_paused, ctftime
from CTFd.utils.decorators import (
    admins_only,
    during_ctf_time_only,
    require_verified_emails,
)
from CTFd.utils.decorators.visibility import (
    check_account_visibility,
    check_challenge_visibility,
    check_score_visibility,
)
from CTFd.utils.humanize.words import pluralize
from CTFd.utils.logging import log
from CTFd.utils.security.signing import serialize
from CTFd.utils.user import (
    authed,
    get_current_team,
    get_current_team_attrs,
    get_current_user,
    get_current_user_attrs,
    is_admin,
)

import json
import os
import subprocess
import tempfile

suricata_namespace = Namespace(
    "suricata", description="Endpoint to retrieve Suricata Secret Stuff"
)

@suricata_namespace.route("/secret_flag")
class SuricataFlag(Resource):
    @during_ctf_time_only
    @require_verified_emails
    def get(self):
        found = False
        user = get_current_user()
        with tempfile.NamedTemporaryFile() as tmp:
            subprocess.call(["jq", "-r", 'select(.alert.signature_id==2024) | .metadata.flowvars[0].winner', '/var/log/suricata/eve.json'], stdout=tmp)
            tmp.seek(0)
            for l in tmp.readlines():
                if l.decode("utf-8")[:-1] == user.name:
                    found = True
                    break
            tmp.close()
        if found:
            flag = Flags.query.filter_by(challenge_id=42).first_or_404()
            schema = FlagSchema()
            response = schema.dump(flag)
            return {"success": True, "data": response}
        else:
            return {"success": False, "help": "You need to have an alert for sid 2024 and your user name as winner : %s" % user.name, "hint": "try /api/v1/suricata/test_rule?rule= and /api/v1/suricata/check_alert?field="}

@suricata_namespace.route("/test_rule")
class SuricataRule(Resource):
    @during_ctf_time_only
    @require_verified_emails
    @validate_args(
        {
            "rule": (str, None),
        },
        location="query",
    )
    def get(self, query_args):
        user = get_current_user()
        with open("/tmp/%s.rules" % user.name, "w") as tmp:
            rule = query_args.pop("rule", None)
            if rule == None:
                return {"success": True, "error": "missing rule argument"}
            tmp.write(rule)
            tmp.close()
        os.makedirs("/tmp/%s_log/" % user.name, exist_ok = True)
        lines = []
        with tempfile.NamedTemporaryFile() as tmp:
            sp = subprocess.call(["suricata", "-k", "none", "-r", "/opt/CTFd/.data/CTFd/uploads/006bc1ca8bb5e8c0e8fc087fd93991e5/test.pcap", "-S", "/tmp/%s.rules" % user.name, "-l", "/tmp/%s_log/" % user.name, "--set", "threshold-file=/etc/suricata/threshold.config"], stdout=tmp)
            tmp.seek(0)
            data = None
            for l in tmp.readlines():
                lines.append(l.decode("utf-8"))
            tmp.close()
        return {"success": True, "returncode": sp, "log": lines}

@suricata_namespace.route("/check_alert")
class SuricataRule(Resource):
    @during_ctf_time_only
    @require_verified_emails
    @validate_args(
        {
            "field": (str, None),
        },
        location="query",
    )
    def get(self, query_args):
        user = get_current_user()
        field = query_args.pop("field", None)
        if field == None:
            return {"success": True, "error": "missing field argument"}
        with tempfile.NamedTemporaryFile() as tmp:
            subprocess.call(["jq", "-c", 'select(.alert.signature_id==24)', "/tmp/%s_log/eve.json" % user.name], stdout=tmp)
            tmp.seek(0)
            data = None
            for l in tmp.readlines():
                data = json.loads(l.decode("utf-8"))
                break
            if data == None:
                return {"success": False, "error": "no alert for sid 24"}
            tmp.close()
            parts = field[1:].split(".")
            for p in parts:
                if p[-1] == ']':
                    if p[:-3] not in data:
                        return {"success": False, "field": p, "error": "not found"}
                    data = data[p[:-3]]
                    if not isinstance(data, list):
                        return {"success": False, "field": p, "error": "not an array"}
                    data = data[int(p[-2:-1])]
                    continue
                if p not in data:
                    return {"success": False, "field": p, "error": "not found"}
                data = data[p]
            if isinstance(data, str):
                return {"success": True, "data": data}
            return {"success": False, "data_type": str(type(data))}
