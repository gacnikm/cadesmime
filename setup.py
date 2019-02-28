import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cadesmime",
    version="0.1",
    author="Matej Gačnik",
    author_email="gacnik.m@gmail.com",
    description="S/MIME with CADES signature",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gacnikm/cadesmime",
    packages=setuptools.find_packages(),
    install_requires=['asn1crypto','cryptography','pytz'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: Communications :: Email",
        "Topic :: Security :: Cryptography"
    ],
)