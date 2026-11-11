def threshold_rule(features, threshold):
    """Alert (1) when flows per window >= threshold."""
    return (features["flow_count"] >= threshold).astype(int)
