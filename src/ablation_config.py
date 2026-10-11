"""Week 3 Day 6: the specialist-ablation configuration (src/ablation_config.py; kept outside src/agents so the agents package keeps exactly the files its Day 3 guard test lists). Pure data and checks. No LLM call, no network, no labels, no file access.

An ablation arm is a set of DISABLED specialists. A disabled specialist is never routed to; the verdict prompt shows it as not_run with the reason
DISABLED_REASON. The default (nothing disabled) is the Day 3 to Day 5 graph, unchanged.

The dependency that shapes the arms: the C2 beaconing analyst runs only when the repeat-contact gate opens, and the gate reads the traffic analyst's own
evidence (supervisor.repeat_contact_flows). With the traffic analyst disabled there is no such evidence, so the gate cannot open and the beaconing analyst is skipped.
So there is no "beaconing without traffic" arm: disabling traffic also removes beaconing (a cascade) and leaves the enrichment agent alone.

The five arms are fixed in advance (pre-registered in the Day 6 plan). Letters are labels only; they carry no order of merit.
"""
from agents import state as S

SPECIALISTS = (S.NODE_TRAFFIC_ANALYST, S.NODE_C2_BEACON_ANALYST, S.NODE_ENRICHMENT_AGENT)
SHORT_NAMES = {"traffic": S.NODE_TRAFFIC_ANALYST, "beacon": S.NODE_C2_BEACON_ANALYST, "enrichment": S.NODE_ENRICHMENT_AGENT}

# The exact words the verdict model sees for a specialist that was switched off by configuration.
DISABLED_REASON = "disabled in this configuration"

ARMS = {
    "A": {"label": "full graph (reference)", "disabled": ()},
    "B": {"label": "no beaconing analyst", "disabled": (S.NODE_C2_BEACON_ANALYST,)},
    "C": {"label": "no enrichment agent", "disabled": (S.NODE_ENRICHMENT_AGENT,)},
    "D": {"label": "no traffic analyst (so no beaconing either: enrichment only)", "disabled": (S.NODE_TRAFFIC_ANALYST,)},
    "E": {"label": "no specialists (verdict step only, alert as given)", "disabled": SPECIALISTS},
}


def normalize(disabled):
    """The disabled set as a tuple in the canonical specialist order. Accepts None, node names or the short names (traffic, beacon, enrichment).
    Raises ValueError for anything else, for a repeated name, and for the verdict node (it cannot be disabled here)."""
    if disabled is None:
        return ()
    if isinstance(disabled, str) or not hasattr(disabled, "__iter__"):
        raise ValueError("disabled must be a list of specialist names")
    names = []
    for item in disabled:
        if not isinstance(item, str):
            raise ValueError("a disabled specialist must be given by name, got " + repr(item))
        name = SHORT_NAMES.get(item, item)
        if name not in SPECIALISTS:
            raise ValueError("cannot disable '" + item + "'. Allowed: " + ", ".join(SPECIALISTS) + " (verdict_node and supervisor cannot be disabled)")
        if name in names:
            raise ValueError("'" + name + "' is listed twice")
        names.append(name)
    return tuple(n for n in SPECIALISTS if n in names)


def enabled_specialists(disabled):
    off = normalize(disabled)
    return tuple(n for n in SPECIALISTS if n not in off)


def cascade_skipped(disabled):
    """Specialists that are not disabled but still cannot run because of the dependency above: the beaconing analyst when the traffic analyst is disabled."""
    off = normalize(disabled)
    if S.NODE_TRAFFIC_ANALYST in off and S.NODE_C2_BEACON_ANALYST not in off:
        return (S.NODE_C2_BEACON_ANALYST,)
    return ()


def effective_specialists(disabled):
    """The specialists that can actually run in a configuration: not disabled and not cascade-skipped. (The beaconing analyst also depends on the repeat-contact gate per alert.)"""
    skipped = cascade_skipped(disabled)
    return tuple(n for n in enabled_specialists(disabled) if n not in skipped)


def arm_for(disabled):
    """The arm letter for a disabled set, or None if it is not one of the five pre-registered arms."""
    off = normalize(disabled)
    for letter, arm in ARMS.items():
        if tuple(arm["disabled"]) == off:
            return letter
    return None


def arm_disabled(letter):
    if letter not in ARMS:
        raise ValueError("unknown arm '" + str(letter) + "'. Arms: " + ", ".join(ARMS))
    return tuple(ARMS[letter]["disabled"])


def describe(disabled):
    """A short plain description for reports."""
    off = normalize(disabled)
    letter = arm_for(off)
    if letter is not None:
        return letter + ": " + ARMS[letter]["label"]
    return "custom: disabled " + (", ".join(off) if off else "nothing")
