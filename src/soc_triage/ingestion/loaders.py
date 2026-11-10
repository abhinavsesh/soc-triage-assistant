import logging

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def load_flows(path):
    """Load a CICIDS2017 flow CSV: strip column names, parse timestamps (day first)."""
    df = pd.read_csv(path, encoding="latin-1")
    df.columns = df.columns.str.strip()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], dayfirst=True)
    logger.info("Loaded %d flows from %s", len(df), path)
    return df


def clean_flows(df, drop_duplicates=False):
    """Replace inf with NaN and report what is affected. Rows are kept by default."""
    df = df.copy()
    num_cols = df.select_dtypes("number").columns
    attack = df["Label"] != "BENIGN"

    n_inf = int(np.isinf(df[num_cols]).sum().sum())
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    rows_nan = df[num_cols].isna().any(axis=1)
    logger.info("Replaced %d inf values with NaN", n_inf)
    logger.info(
        "Rows with any NaN: %d (attack rows: %d). Kept, not dropped.",
        rows_nan.sum(),
        (rows_nan & attack).sum(),
    )

    if drop_duplicates:
        dup = df.duplicated()
        logger.info(
            "Dropping %d duplicate rows (attack rows: %d)", dup.sum(), (dup & attack).sum()
        )
        df = df[~dup]
    return df


def load_auth(path):
    """Load an auth log CSV: parse timestamp, add is_failure (1/0), sort by time."""
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["is_failure"] = (df["result"] == "failure").astype(int)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    logger.info("Loaded %d auth events from %s", len(df), path)
    return df
