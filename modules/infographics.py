import pandas as pd
import matplotlib.pyplot as plt
import ast
from collections import defaultdict


class VulnerabilityAnalysis:
    def __init__(self, base_url, dataframe):
        self.base_url = base_url
        self.df = dataframe
        plt.style.use("ggplot")

    def save_vulnerability_distribution(self, save_path):
        vuln_cols = ["XSS", "SQLi", "CSRF", "Path_Traversal"]
        vuln_counts = self.df[vuln_cols].sum()

        plt.figure(figsize=(10, 6))
        vuln_counts.plot(
            kind="pie",
            autopct="%1.1f%%",
            startangle=140,
            colors=["r", "b", "g", "y"],
            shadow=True,
            explode=[0.05] * 4,
            textprops={"fontsize": 14},
        )
        plt.title(f"{self.base_url} Distribution of Vulnerabilities", fontsize=16)
        plt.ylabel("")
        plt.tight_layout()
        plt.savefig(save_path)

    def save_http_methods_distribution(self, save_path):
        http_methods = self.df["Method"].value_counts()
        plt.figure(figsize=(10, 6))
        http_methods.plot(
            kind="pie",
            autopct="%1.1f%%",
            startangle=140,
            shadow=True,
            explode=[0.05] * len(http_methods),
            textprops={"fontsize": 14},
        )
        plt.title(f"{self.base_url} HTTP Methods Distribution", fontsize=16)
        plt.ylabel("")
        plt.tight_layout()
        plt.savefig(save_path)

    @staticmethod
    def _extract_parameters(params_col):
        params_count = defaultdict(int)
        for param_str in params_col.dropna():
            try:
                params_dict = ast.literal_eval(param_str)
                for key in params_dict:
                    params_count[key] += 1
            except:
                continue
        return params_count

    def save_vulnerable_get_params(self, save_path):
        get_params_counts = self._extract_parameters(self.df["GET Params"])
        plt.figure(figsize=(12, 7))
        pd.Series(get_params_counts).sort_values(ascending=False).head(10).plot(
            kind="bar", color="c", edgecolor="black", alpha=0.75
        )
        plt.title(f"{self.base_url} Top 10 Vulnerable GET Parameters", fontsize=16)
        plt.xlabel("Parameter", fontsize=14)
        plt.ylabel("Occurrences", fontsize=14)
        plt.xticks(rotation=45, fontsize=12)
        plt.tight_layout()
        plt.savefig(save_path)

    def save_vulnerable_post_params(self, save_path):
        post_params_counts = self._extract_parameters(self.df["POST Params"])
        plt.figure(figsize=(12, 7))
        pd.Series(post_params_counts).sort_values(ascending=False).head(10).plot(
            kind="bar", color="m", edgecolor="black", alpha=0.75
        )
        plt.title(f"{self.base_url} Top 10 Vulnerable POST Parameters", fontsize=16)
        plt.xlabel("Parameter", fontsize=14)
        plt.ylabel("Occurrences", fontsize=14)
        plt.xticks(rotation=45, fontsize=12)
        plt.tight_layout()
        plt.savefig(save_path)
