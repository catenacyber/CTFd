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
            return {"success": False, "help": "You need to have an alert for sid 2024 and your user name as winner : %s" % user.name, "hint": "try /api/v1/suricata/test_rule and /api/v1/suricata/check_alerts"}
