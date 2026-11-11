import pandas as pd

from soc_triage.detection.evaluation import best_threshold, evaluate
from soc_triage.detection.rules import threshold_rule


def test_evaluate_counts():
    m = evaluate([1, 1, 0, 0], [1, 0, 1, 0])
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5


def test_evaluate_no_alerts_does_not_crash():
    m = evaluate([0, 0, 1], [0, 0, 0])
    assert m["precision"] == 0.0 and m["recall"] == 0.0


def test_threshold_rule_boundary():
    df = pd.DataFrame({"flow_count": [9, 10, 11]})
    assert threshold_rule(df, 10).tolist() == [0, 1, 1]


def test_best_threshold_separable():
    scores = pd.Series([1, 2, 3, 50, 60])
    y = pd.Series([0, 0, 0, 1, 1])
    t, m = best_threshold(scores, y, range(1, 100))
    assert m["f1"] == 1.0 and 3 < t <= 50
