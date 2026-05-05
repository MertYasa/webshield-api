import numpy as np
import pandas as pd
from src.features.domain_utils import get_registered_domain

def domain_based_split(
    df: pd.DataFrame,
    test_size: float = 0.20,
    random_state: int = 42,
    w_size: float = 1.0,
    w_pos: float = 4.0,
):
    """
    - Domain leakage yok.
    - Domain çıkarılamayan satırlar drop edilir (phishing dataset için daha temiz).
    - Greedy ile satır sayısı ve pozitif oran hedeflenir.
    """
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("DataFrame 'url' ve 'label' kolonlarını içermeli.")

    rng = np.random.RandomState(random_state)

    df = df.copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

    df["domain"] = df["url"].astype(str).apply(get_registered_domain)

    # KRİTİK: unknown yok, temizle
    df["domain"] = df["domain"].replace("", np.nan)
    df = df.dropna(subset=["domain"]).reset_index(drop=True)

    g = df.groupby("domain")["label"].agg(["count", "sum"]).reset_index()
    g.rename(columns={"count": "n", "sum": "pos"}, inplace=True)

    total_n = int(g["n"].sum())
    total_pos = int(g["pos"].sum())

    target_test_n = int(round(total_n * test_size))
    target_test_pos = int(round(total_pos * test_size))

    g = g.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    g = g.sort_values("n", ascending=False).reset_index(drop=True)

    test_domains = []
    cur_test_n = 0
    cur_test_pos = 0

    def score(test_n, test_pos):
        return (w_size * abs(target_test_n - test_n)) + (w_pos * abs(target_test_pos - test_pos))

    for _, row in g.iterrows():
        d = row["domain"]
        dn = int(row["n"])
        dpos = int(row["pos"])

        s_put_test = score(cur_test_n + dn, cur_test_pos + dpos)
        s_put_train = score(cur_test_n, cur_test_pos)

        if s_put_test < s_put_train:
            test_domains.append(d)
            cur_test_n += dn
            cur_test_pos += dpos
        elif s_put_test == s_put_train:
            if rng.rand() < 0.5:
                test_domains.append(d)
                cur_test_n += dn
                cur_test_pos += dpos

    test_domains = set(test_domains)

    test_df = df[df["domain"].isin(test_domains)].reset_index(drop=True)
    train_df = df[~df["domain"].isin(test_domains)].reset_index(drop=True)

    return train_df, test_df