import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse, unquote, parse_qs, urlsplit, parse_qsl
from sklearn.metrics import f1_score
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
import xgboost as xgb
import sys
import matplotlib.pyplot as plt
import warnings
import seaborn as sns
import os
from scipy.stats import norm
from modules.logger_config import setup_logger
import traceback

warnings.simplefilter(action="ignore", category=FutureWarning)


class URLClassifier:
    def __init__(self, base_url, threshold=0.3, n_estimators=1000):
        self.threshold = threshold
        self.base_url = base_url
        self.n_estimators = n_estimators
        self.logger = setup_logger(__name__)
        self.logger.propagate = False
        self.filtered_data = None
        self.logger.info("Initializing URL Classifier...\n")
        self.tfidf_vectorizer = TfidfVectorizer(max_features=300)
        self.suspicious_tokens = [
            "script",
            "alert",
            "<",
            ">",
            "&",
            "!",
            "eval(",
            "fromCharCode(",
            "<svg",
            "onload",
            "onerror",
            "img",
            "body",
            "input",
            "onmouseover",
            "confirm(",
            "prompt(",
            "document.cookie",
            "localStorage",
            "or 1=1",
            "union",
            "select",
            "-- ",
            "/*",
            "*/",
            "drop",
            "delete",
            "insert",
            "update",
            "exec(",
            "execute(",
            "concat",
            "substr(",
            "ascii(",
            "declare",
            "information_schema",
            "<iframe",
            "../",
            "./",
            "root",
            "/etc/passwd",
            "C:\\",
            "|",
            "$",
            ";",
            "`",
            "id",
            "cmd=",
            "exec(",
            "login",
            "register",
            "logout",
            "edit",
            "CSRFName",
            "CSRFToken",
            "csrf_token",
            "anticsrf",
            "__RequestVerificationToken",
            "VerificationToken",
            "form_build_id",
            "nonce",
            "authenticity_token",
            "csrf_param",
            "TransientKey",
            "csrf",
            "AntiCSURF",
            "YII_CSRF_TOKEN",
            "yii_anticsrf",
            "[_token]",
            "_csrf_token",
            "csrf-token",
            "csrfmiddlewaretoken",
            "ccm_token",
            "XOOPS_TOKEN_REQUEST",
            "_csrf",
            "and",
            "not",
            "or",
            "`",
            "''",
            "$",
            "eval(",
            "assert(",
            "token",
            "auth",
            "hash",
            "secret",
            "verify",
            "email",
            "e-mail",
            "password",
            "profile",
            "update",
            "delete",
            "add",
            "share",
            "forgot-password",
            "forgotpassword",
            "forgot",
            "username",
            "user",
            "send",
            "checkout",
            "vote",
            "visit",
            "pay",
            "payment",
            "request",
            "review",
            "follow",
            "unfollow",
            "transfer",
            "subscribe",
            "unsubscribe",
            "donate",
            "money",
            "comment",
            "change",
            "coupon",
            "apply",
        ]

        self.model = xgb.XGBClassifier(
            objective="binary:logistic",
            eval_metric="logloss",
            n_estimators=self.n_estimators,
        )

    @staticmethod
    def calculate_entropy(text):
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy

    def domain_features(self, urls):
        parsed_urls = [urlparse(url) for url in urls]

        entropy = np.array([self.calculate_entropy(url) for url in urls]).reshape(-1, 1)

        query_lengths = np.array(
            [len(unquote(parsed_url.query)) for parsed_url in parsed_urls]
        ).reshape(-1, 1)
        query_params_count = np.array(
            [len(parse_qs(parsed_url.query)) for parsed_url in parsed_urls]
        ).reshape(-1, 1)
        query_punctuations = np.array(
            [
                sum(
                    c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
                    for c in unquote(parsed_url.query)
                )
                for parsed_url in parsed_urls
            ]
        ).reshape(-1, 1)

        features = np.hstack(
            [entropy, query_lengths, query_params_count, query_punctuations]
        )

        domain_features = []
        for token in self.suspicious_tokens:
            token_count_name = f"token_{token}_count"
            token_counts = np.array(
                [unquote(url).lower().count(token) for url in urls]
            ).reshape(-1, 1)
            features = np.hstack([features, token_counts])
            domain_features.append(token_count_name)

        return features

    def load_data(self):
        try:
            self.logger.info("Loading data...\n")
            self.training_data = pd.read_csv(
                sys.path[0] + "/ML/Data_Files/Training_data.csv"
            )
            self.test_data = pd.read_csv(
                sys.path[0]
                + "/results/"
                + self.base_url
                + f"/DF/{self.base_url}_crawled_endpoints.csv"
            )
            if self.training_data.empty or self.test_data.empty:
                self.logger.error("Either the test set or the training set is empty\n")
                quit()
            else:
                # Drop duplicates
                self.training_data.drop_duplicates(keep="first", inplace=True)
                self.test_data.drop_duplicates(keep="first", inplace=True)
                self.logger.info(f"Training data shape: {self.training_data.shape}")
                self.logger.info(f"Test data shape: {self.test_data.shape}")

        except FileNotFoundError:
            self.logger.error("Error loading data: file not found\n")
            raise
        except Exception as e:
            self.logger.error(f"Error loading data: {e}\n")
            raise

    def clean_url(self, url):
        #    Make sure the URL is a string
        url = str(url)
        url = unquote(url.split(" ")[0]).lower()

        # Step 1: Parse the URL
        parsed_url = urlsplit(url)
        path = parsed_url.path
        query = parsed_url.query

        # Step 2: Split the path and clean up
        path_parts = path.strip("/").split("/")
        cleaned_path = " ".join(path_parts)

        # Step 3: Parse the query string
        query_parts = parse_qsl(query)
        cleaned_query = " ".join(["{} {}".format(k, v) for k, v in query_parts])

        # Step 4: Combine the cleaned path and query string
        cleaned_string = "{} {}".format(cleaned_path, cleaned_query)

        # Step 5: Lowercase and remove non-alphanumeric characters (except spaces)
        cleaned_string = "".join(
            char if char.isalnum() or char.isspace() else " " for char in cleaned_string
        ).lower()

        # List of famous extensions
        extensions = [
            "jsp",
            "php",
            "js",
            "txt",
            "asp",
            "aspx",
            "html",
            "xml",
            "cgi",
            "py",
            "json",
            "conf",
            "htaccess",
        ]

        # Step 6: Check if any of the extension is in cleaned string and remove it
        for extension in extensions:
            if extension in cleaned_string:
                cleaned_string = cleaned_string.replace(extension, "")

        return cleaned_string

    def preprocess_data(self):
        try:
            self.logger.info("Vectorizing the URL data with TF-IDF\n")
            train_urls = self.training_data["URL"]
            test_urls = self.test_data["URL"]

            train_pq = train_urls.apply(self.clean_url)
            test_pq = test_urls.apply(self.clean_url)

            self.tfidf_vectorizer.fit(train_pq)

            X_train_tfidf = self.tfidf_vectorizer.transform(train_pq)
            X_test_tfidf = self.tfidf_vectorizer.transform(test_pq)

            self.X_test_tfidf = X_test_tfidf

            X_train_domain = self.domain_features(train_urls)
            X_test_domain = self.domain_features(test_urls)

            # Ensure domain features are in the correct 2D shape
            if len(X_train_domain.shape) == 1:
                X_train_domain = X_train_domain.reshape(-1, 1)
            if len(X_test_domain.shape) == 1:
                X_test_domain = X_test_domain.reshape(-1, 1)

            # Convert domain features to sparse format
            X_train_domain_sparse = csr_matrix(X_train_domain)
            X_test_domain_sparse = csr_matrix(X_test_domain)

            # Combine the adjusted tf-idf features with the domain features
            X_train_combined = hstack([X_train_tfidf, X_train_domain_sparse])
            self.X_test_combined = hstack([self.X_test_tfidf, X_test_domain_sparse])

            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                X_train_combined,
                self.training_data["classification"],
                test_size=0.2,
                stratify=self.training_data["classification"],
                random_state=42,
            )

            self.logger.info(
                f"Data preprocessed. Training set shape: {self.X_train.shape}. Test set shape: {self.X_test.shape}."
            )

        except Exception as e:
            self.logger.error(f"Error during data preprocessing: {e}\n")
            print(traceback.print_exc())
            raise

    def train(self):
        try:
            self.logger.info(
                f"Training XGBoost model with {self.n_estimators} estimators\n"
            )
            self.model.fit(self.X_train, self.y_train)
            y_pred = self.model.predict(self.X_test)
            accuracy = accuracy_score(self.y_test, y_pred)
            classification_rep = classification_report(self.y_test, y_pred)
            f1 = f1_score(self.y_test, y_pred, average="weighted")
            precision = precision_score(self.y_test, y_pred, average="weighted")
            recall = recall_score(self.y_test, y_pred, average="weighted")

            self.logger.info("Model trained successfully\n")
            print(
                f"Training Accuracy: {self.model.score(self.X_train, self.y_train)*100:.2f}%"
            )
            print(f"Testing Accuracy: {accuracy*100:.2f}%")
            print(f"F1 Score: {f1:.2f}")
            print(f"Precision: {precision:.2f}")
            print(f"Recall: {recall:.2f}")
            print("\nClassification Report:\n", classification_rep)

        except Exception as e:
            self.logger.error(f"Error during model training: {e}\n")
            raise

    def plot_feature_importance(self):
        try:
            directory = f"{sys.path[0]}/results/{self.base_url}/IMG/"
            # Step 1: Get feature importances
            feature_importances = self.model.feature_importances_

            # Step 2: Get feature names
            # TF-IDF feature names
            tfidf_feature_names = self.tfidf_vectorizer.get_feature_names_out().tolist()

            # Domain feature names
            domain_feature_names = [
                "entropy",
                "query_length",
                "query_params_count",
                "query_punctuations",
            ]
            for token in self.suspicious_tokens:
                domain_feature_names.append(f"token_{token}_count")

            # Combine TF-IDF and domain feature names
            feature_names = tfidf_feature_names + domain_feature_names

            # Step 3: Create a pandas dataframe and sort it based on feature importances
            feature_importance_df = pd.DataFrame(
                {"Feature": feature_names, "Importance": feature_importances}
            )
            feature_importance_df = feature_importance_df.sort_values(
                by="Importance", ascending=False
            )

            # Step 4: Plot feature importances (Just the first 10)
            top_features = feature_importance_df.head(10)
            plt.figure(figsize=(10, 6))
            sns.barplot(x="Importance", y="Feature", data=top_features)
            plt.title("XGBoost Top 10 Feature Importance")
            plt.xlabel("Importance")
            plt.ylabel("Feature")
            plt.show()
            plt.savefig(directory + f"{self.base_url}_feature_importance.png")
        except Exception as e:
            self.logger.error(f"Error during feature importance plotting: {e}\n")
            raise

    def predict(self):
        try:
            # Check if test_data has been set
            if hasattr(self, "test_data"):
                # Predict the probabilities for each class
                probabilities = self.model.predict_proba(self.X_test_combined)
                class1 = probabilities[:, 1]

                # Add a single column for the probability of being class 1
                self.test_data["Probabilities"] = class1

                self.logger.info("Probabilities column added successfully\n")

            else:
                self.logger.error(
                    "test_data is not defined. Please set test_data before predicting.\n"
                )
                raise ValueError(
                    "test_data is not defined. Please set test_data before predicting."
                )

            # Filter the data based on the threshold
            self.filtered_data = self.test_data[
                self.test_data["Probabilities"] < self.threshold
            ]

            self.logger.info(
                "Filtered data created successfully based on the threshold\n"
            )

        except Exception as e:
            self.logger.error(f"Error during prediction: {e}\n")
            raise

    def visualize_results(self):
        try:
            directory = f"{sys.path[0]}/results/{self.base_url}/IMG/"
            # Check if directory exists, if not, create it
            if not os.path.exists(directory):
                os.makedirs(directory)
            self.logger.info(f"Saving visualization results in path: {directory}")

            # Calculate the data points
            original_data_points = len(self.test_data)
            filtered_data_points = len(self.filtered_data)

            # Data for pie chart
            labels = ["Original Data", "Filtered Data"]
            sizes = [original_data_points - filtered_data_points, filtered_data_points]
            colors = ["lightgray", "lightblue"]
            explode = (0, 0.1)  # explode 2nd slice for emphasis

            # Plot pie chart
            plt.figure(figsize=(8, 6))
            plt.pie(
                sizes,
                explode=explode,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                shadow=True,
                startangle=140,
            )
            plt.axis(
                "equal"
            )  # Equal aspect ratio ensures that pie is drawn as a circle.
            plt.title(f"{self.base_url} Data Comparison (Threshold: {self.threshold})")

            # Save the chart
            plt.savefig(directory + f"{self.base_url}_data_comparison_pie_chart.png")

            # Save the histogram of probabilities with overlaid PDF
            plt.figure(figsize=(10, 5))
            sns.histplot(
                self.filtered_data["Probabilities"],
                bins=50,
                kde=True,
                color="darkblue",
                line_kws={"linewidth": 2},
            )

            # Overlay with Gaussian curve
            mu, std = norm.fit(self.filtered_data["Probabilities"])
            xmin, xmax = plt.xlim()
            x = np.linspace(xmin, xmax, 100)
            p = norm.pdf(x, mu, std)
            plt.plot(x, p, "r-", linewidth=2)
            plt.title(
                f"{self.base_url} Distribution of Predicted Probabilities with Gaussian Fit"
            )
            plt.xlabel("Probability")
            plt.ylabel("Number of URLs")
            plt.savefig(directory + f"{self.base_url}_probabilities_histogram.png")

            # Save the figure with increased size
            plt.savefig(
                directory + f"{self.base_url}_feature_importances_with_real_names.png",
                bbox_inches="tight",  # Optional: this ensures that the whole plot is saved
            )
        except Exception as e:
            self.logger.error(f"Error during visualization: {e}\n")
            print(traceback.print_exc())
            raise

    def save_results(self):  # New method to save the filtered dataframe
        try:
            path = sys.path[0] + "/results/" + self.base_url + "/DF/"
            self.logger.info(f"Saving filtered data to path: {path}")
            self.filtered_data.to_csv(
                path + f"{self.base_url}_filtered_data.csv",
                index=False,
            )
        except Exception as e:
            self.logger.error(f"Error during saving results: {e}\n")
            raise

    def run(self):
        try:
            self.load_data()  # Load the data
            self.preprocess_data()  # Pre-process the data
            self.train()  # Train the XGBoost
            self.predict()
            self.visualize_results()  # Visualize the results
            self.plot_feature_importance()
            self.save_results()  # Save the filtered results to a CSV
        except Exception as e:
            self.logger.error(f"Error during execution: {e}\n")
            raise
        except KeyboardInterrupt:
            sys.exit(0)
