# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import pandas as pd
import json
import sys
import os


class SerializePipeline:
    def __init__(self):
        self.items = []

    def process_item(self, item, spider):
        self.items.append(item)
        return item

    def close_spider(self, spider):
        if not self.items:
            spider.logger.warning("No items to process in pipeline.")
            return

        df = pd.DataFrame(self.items)
        base_url = self.items[0].get("base_url")
        if base_url is not None:
            df["GET Params"] = df["GET Params"].apply(
                lambda x: json.dumps(x) if isinstance(x, dict) else x
            )
            df["POST Params"] = df["POST Params"].apply(
                lambda x: json.dumps(x) if isinstance(x, dict) else x
            )

            directory = f"{sys.path[0]}/results/{base_url}/DF/"

            # Check if directory exists, if not, create it
            if not os.path.exists(directory):
                os.makedirs(directory)

            path = directory + f"{base_url}_crawled_endpoints.csv"
            final_df = df.drop_duplicates()
            final_df.to_csv(path, index=False)
        else:
            spider.logger.warning(
                "base_url is not defined in items. Unable to process pipeline."
            )
