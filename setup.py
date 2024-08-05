import setuptools

setuptools.setup(
    name="file-validation",
    version="1.0",
    description="File validation library.",
    url="https://code.overnitecbt.com/calverson/validation/",
    author="Claire Alverson",
    author_email="calverson@overnitecbt.com",
    install_requires=[
        "requests",
        ],
    packages=[
        "file-validation", 
        "fleep",
        ],
    package_data={'fleep': ['data.json']},
    package_dir={"": "src"},
    classifiers = [
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        ],
    python_requires=">=3.1",
    include_package_data=True,
    zip_safe=False
)
