# file-validation


Comprehensive tests to validate a file based on file signature.


## Usage

`pip install file-validation`

## Methods

Tests the hashed file value against a dataset of known virus hashes (provided by MalwareBazaar)

`virus_test(uploaded_file)`

Tests the file name to ensure it is allowed.

`regex_file_name_test(uploaded_file, allowed_extensions=allowed_extensions, regex=regex)`

Tests the file to ensure the file signature matches with the corressponeding mime type, extension and given size.

`file_type_test(uploaded_file, allowed_types=allowed_types, allowed_mimes=allowed_mimes, allowed_extensions=allowed_extensions, allowed_size=allowed_size)`

Runs the file through all of the above tests.

`acceptable_file(uploaded_file, allowed_types, allowed_mimes, allowed_extensions, allowed_size, regex)`


## Disclaimer

The authors and contributors of this package can not be held liable for any false positives or damage caused by the use of the file-validation package.