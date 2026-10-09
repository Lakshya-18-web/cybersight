"""MITRE ATT&CK tools: look a technique up by id, or search the reference by words.

  mitre_lookup  one technique: name, tactics, summary, what it can look like in flow records, its parent or sub-techniques
  mitre_search  techniques whose id, name, tactic or description match some words (deterministic ranking)

These read tools/mitre_reference.py only. They never read the answer key that belongs to the evaluation harness, and nothing
here maps a dataset class to a technique. The tools describe techniques. Choosing one is the analyst's job.
"""
import re

from . import mitre_reference as ref
from .base import P, ToolSpec, ToolFailure, CODE_NOT_FOUND, CODE_INVALID

_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
MAX_RESULTS = 10
DEFAULT_RESULTS = 5
_WORD = re.compile(r"[a-z0-9]+")
_ID_IN_TEXT = re.compile(r"t[0-9]{4}(?:\.[0-9]{3})?")
_STOP = {"the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "with", "from", "by", "is", "are"}


def _brief(t):
    return {"technique_id": t["technique_id"], "name": t["name"], "tactics": t["tactics"]}


class MitreTools:
    def lookup(self, c):
        technique_id = c["technique_id"].upper()
        if not _ID.match(technique_id):
            raise ToolFailure(CODE_INVALID, "technique_id must look like T1110 or T1110.001")
        t = ref.TECHNIQUES.get(technique_id)
        if t is None:
            parent = technique_id.split(".")[0]
            hint = ""
            if "." in technique_id and parent in ref.TECHNIQUES:
                hint = " Its parent " + parent + " (" + ref.TECHNIQUES[parent]["name"] + ") is in the table."
            raise ToolFailure(CODE_NOT_FOUND, technique_id + " is not in the curated ATT&CK table. That does not mean it is not a real technique; check attack.mitre.org." + hint)
        out = dict(t)
        out["tactics"] = list(t["tactics"])
        out["parent"] = _brief(ref.TECHNIQUES[t["parent_id"]]) if t["parent_id"] else None
        out["subtechniques"] = [_brief(s) for sid, s in sorted(ref.TECHNIQUES.items()) if s["parent_id"] == technique_id]
        out["source"] = ref.SOURCE_NOTE
        return out

    def search(self, c):
        words = [w for w in _WORD.findall(c["query"].lower()) if w not in _STOP and len(w) >= 2]
        if not words:
            raise ToolFailure(CODE_INVALID, "query has no searchable words")
        tactic = c["tactic"]
        ids_named = set(_ID_IN_TEXT.findall(c["query"].lower()))  # a whole id such as t1595.001 is one token, not two words
        scored = []
        for tid, t in ref.TECHNIQUES.items():
            if tactic is not None and tactic not in [x.lower() for x in t["tactics"]]:
                continue
            name = t["name"].lower()
            tactics = " ".join(t["tactics"]).lower()
            summary = t["summary"].lower()
            flows = t["flow_observables"].lower()
            score = 0
            if tid.lower() in ids_named:
                score += 10
            for w in words:
                score += 3 * (w in name) + 2 * (w in tactics) + (w in summary) + (w in flows)
            if score > 0:
                scored.append((-score, tid))
        scored.sort()
        picked = [tid for _, tid in scored[:c["limit"]]]
        return {"query": c["query"], "tactic_filter": tactic, "total_matches": len(scored), "returned": len(picked),
                "techniques": [dict(_brief(ref.TECHNIQUES[tid]), score=-s, summary=ref.TECHNIQUES[tid]["summary"]) for (s, tid) in scored[:c["limit"]]],
                "source": ref.SOURCE_NOTE}

    def specs(self):
        return [
            ToolSpec("mitre_lookup", "Look up one MITRE ATT&CK technique by id (for example T1110 or T1110.001): name, tactics, summary, what it can look like in flow records, "
                     "parent and sub-techniques. Curated subset; a missing id is reported, not guessed.",
                     {"technique_id": P("string", "ATT&CK technique id, such as T1071 or T1071.001.", required=True, max_length=12)}, self.lookup),
            ToolSpec("mitre_search", "Search the curated ATT&CK table by words (for example 'brute force login' or 'flood web server'), optionally within one tactic. Returns the best matches.",
                     {"query": P("string", "Words describing the behaviour.", required=True, max_length=120),
                      "tactic": P("enum", "Only techniques in this tactic.", enum=[t.lower() for t in ref.TACTICS]),
                      "limit": P("integer", "Maximum techniques returned.", default=DEFAULT_RESULTS, minimum=1, maximum=MAX_RESULTS)}, self.search),
        ]
