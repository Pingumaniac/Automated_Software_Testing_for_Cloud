import string
import random
import json
import logging
import os
from yaspin import yaspin
from pathlib import Path


class RandomJSONGenerator:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.random_docs_folder = os.path.join(os.path.dirname(__file__), 'generated_docs')
        Path(self.random_docs_folder).mkdir(parents=True, exist_ok=True)
        self.set_logger()

    def set_logger(self):
        """Sets up the logger for the generator."""
        self.logger = logging.getLogger('RandomJSONGenerator')
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_random_string(self, length=10):
        """Generates a random string of a given length."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_random_int(self):
        """Generates a random integer."""
        return random.randint(1, 1000)

    def generate_random_bool(self):
        """Generates a random boolean value."""
        return random.choice([True, False])

    def generate_random_float(self):
        """Generates a random float value."""
        return round(random.uniform(1, 1000), 2)

    def generate_random_json_document(self, doc_size=25):
        """Generates a random JSON document with mixed data types."""
        document = {}
        for _ in range(doc_size):
            key = self.generate_random_string(10)
            value_type = random.choice([self.generate_random_string, self.generate_random_int,
                                        self.generate_random_bool, self.generate_random_float])
            document[key] = value_type()
        return document

    def generate_random_docs(self, num_docs=1000, doc_size=25):
        """Generates a specified number of random JSON documents and writes them to the generated_docs folder."""
        self.logger.info(f"Generating {num_docs} random JSON documents.")
        with yaspin().white.bold.shark.on_blue as sp:
            for i in range(num_docs):
                self.logger.debug(f'Generating document {i + 1}/{num_docs}')
                document = self.generate_random_json_document(doc_size=doc_size)
                filename = f'{self.generate_random_string(10)}.json'
                self.logger.debug(f'Writing document {i + 1} to {filename}')
                with open(os.path.join(self.random_docs_folder, filename), 'w') as f:
                    json.dump(document, f, indent=2)
        self.logger.info(f"Successfully generated {num_docs} JSON documents in {self.random_docs_folder}.")

    def read_random_doc(self):
        """Reads a random JSON document from the generated_docs folder."""
        files = os.listdir(self.random_docs_folder)
        if not files:
            self.logger.error("No documents found in the generated_docs folder.")
            return None
        random_file = random.choice(files)
        with open(os.path.join(self.random_docs_folder, random_file), 'r') as f:
            document = json.load(f)
        self.logger.info(f"Loaded document {random_file}")
        return document


def main():
    """Generate a set of random JSON documents."""
    generator = RandomJSONGenerator(verbose=True)
    generator.generate_random_docs(num_docs=500, doc_size=30)


if __name__ == "__main__":
    main()
