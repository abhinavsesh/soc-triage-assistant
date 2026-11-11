from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


def evaluate(y_true, y_pred):
    """Confusion counts plus precision, recall, F1 and false-positive rate."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def best_threshold(scores, y_true, candidates):
    """Pick the candidate threshold with the best F1 (alert if score >= threshold).

    Ties go to the first (lowest) candidate, which favours recall.
    Only call this on TRAINING data.
    """
    best = None
    for t in candidates:
        m = evaluate(y_true, (scores >= t).astype(int))
        if best is None or m["f1"] > best[1]["f1"]:
            best = (t, m)
    return best
