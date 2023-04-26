from setuptools import setup, find_packages

with open("README.md", "r") as readme_file:
    readme = readme_file.read()

requirements = ["requests"]

setup(
    name="vault-dump",
    version="0.0.4",
    author="Daniel Popescu",
    author_email="danielpops@gmail.com",
    description="A package to dump the configuration settings for a running hashicorp vault instance",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/danielpops/vault-dump",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.7",
    ],
    entry_points = {
        "console_scripts": [
            "vault-dump=vault_dump.main:main"
        ]
    },
)

