"""Ground truth for scoring. EVALUATION HARNESS ONLY.

The agent, the prompt builder and the runner must never import this module. The test suite checks this.
It reads only the dev labels. The frozen labels are opened only through eval_io.py during the final runs.
"""
import eval_io


def load_dev_labels():
    return eval_io.load_labels("dev")


def load_answer_key():
    return eval_io.load_mitre_map()


def check_alignment(alerts, labels):
    """The alert file and the label file must list the same ids in the same order."""
    if list(alerts["alert_id"]) != list(labels["alert_id"]):
        raise ValueError("alert ids and label ids differ or are in a different order")
    return True
