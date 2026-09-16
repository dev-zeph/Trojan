"""
Provision the Trojan Errors storage backend (Bugsink) for local development.

Run via:  bugsink-manage shell < provision.py     (or the wrapper in setup.sh)

Idempotent. Creates:
  - a team + project to hold Trojan-ingested events
  - a full-access API token the Trojan shim uses to READ issues back out
  - prints a JSON blob that setup.sh writes to crash-analytics/runtime.json

Nothing here is customer-visible. Customers never see or log into Bugsink --
they auth against Trojan, and the Trojan shim is the only thing that talks to
this service. See backend/src/errors/ for that shim.
"""

import json
import sys

from django.contrib.auth import get_user_model

from bsmain.models import AuthToken
from projects.models import Project, ProjectMembership, ProjectRole
from teams.models import Team, TeamMembership, TeamRole

TEAM_NAME = "Trojan"
PROJECT_NAME = "trojan-errors"
TOKEN_DESCRIPTION = "trojan-errors-shim"

User = get_user_model()

# The superuser created by setup.sh. Team/project need an owner; the shim's
# token is a service token (not user-bound), so this user is only a placeholder.
admin = User.objects.filter(is_superuser=True).order_by("id").first()
if admin is None:
    sys.stderr.write("provision: no superuser found -- run createsuperuser first\n")
    raise SystemExit(1)

team, _ = Team.objects.get_or_create(name=TEAM_NAME)
TeamMembership.objects.get_or_create(
    team=team, user=admin, defaults={"role": TeamRole.ADMIN, "accepted": True}
)

project, _ = Project.objects.get_or_create(
    name=PROJECT_NAME, defaults={"team": team}
)
if project.team_id != team.id:
    project.team = team
    project.save(update_fields=("team",))

ProjectMembership.objects.get_or_create(
    project=project, user=admin, defaults={"role": ProjectRole.ADMIN, "accepted": True}
)

# Reuse an existing live token if we already provisioned one, so re-running
# setup.sh doesn't invalidate a runtime.json the user already has.
token = (
    AuthToken.objects.filter(description=TOKEN_DESCRIPTION, expires_at=None)
    .order_by("-created_at")
    .first()
)
if token is None:
    token = AuthToken.create_full_access(description=TOKEN_DESCRIPTION)

print(
    "TROJAN_PROVISION_JSON:"
    + json.dumps(
        {
            "backendProjectId": str(project.id),
            "backendPublicKey": project.sentry_key.hex,
            "backendDsn": project.dsn,
            "backendApiToken": token.token,
        }
    )
)
