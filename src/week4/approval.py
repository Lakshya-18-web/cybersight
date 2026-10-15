"""The approval service: the only code that turns a human decision into a stored decision, and a stored approval into a SIMULATED execution record.

Rules (enforced here for a clear early error, and again by the database, which is the authority):
  * only an authenticated, active analyst with the role approver or admin may decide a proposal or record its simulated execution;
  * a proposal is decided exactly once; a repeat of the same request is acknowledged (idempotent) and any other attempt is a conflict;
  * a rejected or pending proposal can never be executed;
  * "executing" means writing a row that says "simulated". No code in this project contacts a firewall, an endpoint agent or any network device.
The caller must pass the identity it authenticated (the API takes it from the credential, never from the request body). A missing identity fails closed.
"""
from week4.db.repository import ANALYST_ID_RE

APPROVER_ROLES = ("approver", "admin")
READ_ROLES = ("viewer", "analyst", "approver", "admin")

REASON_MAX = 1000


class AuthorizationError(Exception):
    pass


class Principal:
    """An authenticated person, as stored in the analysts table. Build it with ApprovalService.principal()."""

    def __init__(self, analyst_id, role, active=True):
        self.analyst_id, self.role, self.active = analyst_id, role, active

    def can_read(self):
        return self.active and self.role in READ_ROLES

    def can_decide(self):
        return self.active and self.role in APPROVER_ROLES


class SimulatedExecutor:
    """The only executor there is. It records that an approved action would have been carried out; it carries nothing out."""
    mode = "simulated"

    def __init__(self, repo):
        self.repo = repo

    def execute(self, action_id, actor):
        return self.repo.simulate_execution(action_id, actor)


class ApprovalService:
    def __init__(self, repo, executor=None):
        self.repo = repo
        self.executor = executor or SimulatedExecutor(repo)
        if getattr(self.executor, "mode", None) != "simulated":
            raise ValueError("only a simulated executor is allowed in this project")

    def principal(self, analyst_id):
        """The stored identity for an authenticated analyst id, or None when unknown or malformed."""
        if not isinstance(analyst_id, str) or not ANALYST_ID_RE.match(analyst_id):
            return None
        row = self.repo.get_analyst(analyst_id)
        return Principal(row["analyst_id"], row["role"], row["active"]) if row else None

    def _require_decider(self, principal):
        if principal is None or not isinstance(principal, Principal) or not principal.can_decide():
            raise AuthorizationError("only an active approver or admin may do this")

    def decide(self, principal, action_id, decision, reason, idempotency_key):
        """-> the repository's decision dict. Raises AuthorizationError before touching the store when the caller may not decide."""
        self._require_decider(principal)
        if isinstance(reason, str) and len(reason) > REASON_MAX:
            raise ValueError("reason is longer than %d characters" % REASON_MAX)
        return self.repo.decide_action(action_id, decision, principal.analyst_id, reason, idempotency_key)

    def execute_simulated(self, principal, action_id):
        self._require_decider(principal)
        return self.executor.execute(action_id, principal.analyst_id)
