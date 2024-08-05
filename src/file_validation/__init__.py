import re
import hashlib
import requests
import fleep
import json


def virus_test(uploaded_file):
    '''
    Tests if a file is a known virus. 

    This uses a sha256 hash to hash the file and then uses MalwareBazzar to test the hash against known virus hashes.

    Parameters
    ----------
    uploaded_file : <class 'django.core.files.uploadedfile.TemporaryUploadedFile'>
        A Django model with FileField.    

    testing hash (is a virus hash): 094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d

    '''

    hashed_file = hashlib.sha256()
    data = uploaded_file.read()
    hashed_file.update(data)
    uploaded_file_hash = hashed_file.hexdigest()

    data = {
        'query': 'get_info',
        'hash': ''+uploaded_file_hash+'',
        'field': 'sha256_hash'
    }

    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15)
    except:
        raise Exception('Malware Bazaar is experiencing issues. Try again later.')
    else:
        json_response = response.content.decode("utf-8", "ignore")
        parsed_response = json.loads(json_response)
        query_status = parsed_response["query_status"]
        if query_status == "hash_not_found":
            pass
        elif query_status == "ok":
            raise Exception("Attempted known virus upload.")
        else:
            raise Exception("Unknown error. Try again later.")


def regex_file_name_test(uploaded_file, allowed_extensions: list = [], regex: str = None):
    '''
    Test to check if the file name is acceptable.

    Parameters
    ----------
    uploaded_file : <class 'django.core.files.uploadedfile.TemporaryUploadedFile'>
        A Django model with FileField.

    allowed_extensions : list (of str)
        The file extensions that the file is validated against. 
        str format : "ext1" (without periods ("."); ["ext1", "ext2", ...] not [".ext1", ".ext2", ...])
        Keep in mind that certain operating systems are case sensitve (Linux) while others are case insensitve (Windows) in regards to extensions.
        Because of OS differences, it is your responsibility to provide the correct casing in the extension list.

    regex : str, optional
        A string to ensure the file name is not malicious. 
        The string should not include the extensions as this function will add that in.

    '''

    regex_extensions = "|".join(allowed_extensions)
    if regex:
        regex = regex+"\.(?:"+regex_extensions+")$"
    else:
        regex = "^(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-\_\ ]{0,50})?(?:[a-zA-Z0-9])?\.(?:"+regex_extensions+")$"
    uploded_file_name = uploaded_file.name
    file_name_validation = re.search(regex, uploded_file_name)
    if not file_name_validation:
        raise Exception('Uploaded file has a prohibited name.')
    

def file_type_test(uploaded_file, allowed_types: list = [], allowed_mimes: list = [], allowed_extensions: list = [], allowed_size: int = 100000):
    '''
    Test to check if the file signature matches all the other attributes of the title. 
    
    Uses a modified version of the fleep package. fleep/data.json holds the file signature information. If you wish to check more files, you must add them there.
    "raw-image"
    
    Parameters
    ----------

    uploaded_file : <class 'django.core.files.uploadedfile.TemporaryUploadedFile'>
        A model with FileField.

    allowed_types : list (of str)
        The file types that the file is validated against.
        str format : "type" (["type1", "type2", ...])

    allowed_mimes : list (of str)
        The file mime types that the file is validated against.
        str format "type/subtype" 
   
    allowed_extensions : list (of str)
        The file extensions that the file is validated against. 
        str format : "ext1" (without periods ("."); ["ext1", "ext2", ...] not [".ext1", ".ext2", ...])
        Keep in mind that certain operating systems are case sensitve (Linux) while others are case insensitve (Windows) in regards to extensions.
        Because of OS differences, it is your responsibility to provide the correct casing in the extension list.

    allowed_size : int
        The maximum file size that the file is validated against.    
        
    '''

    uploaded_file_path = uploaded_file.temporary_file_path()
    uploaded_mime = uploaded_file.content_type
    uploaded_extension = uploaded_file.file.name.split('.')[-1]
    with open(uploaded_file_path , "rb") as file:
        validation = fleep.get(file.read(128))
        info_type = validation['info'].type
        info_extension = validation['info'].extension
        info_mime = validation['info'].mime
        info_all = validation['data']

    for t in allowed_types:
        if t in info_type:
            type = t
            break
    for m in allowed_mimes:
        if m in info_mime:
            mime = m
            break
    for e in allowed_extensions:
        if e in info_extension:
            extension = e
            break

    if uploaded_file.size <= allowed_size:
        size = uploaded_file.size

    if not type:
        raise Exception('File type not supported.')
    if not mime:
        raise Exception('File mime not supported.')
    if not extension:
        raise Exception('File extension not supported.')
    if not size:
        raise Exception('File size not supported.')

    # if acceptable file has all the matching features (type, extension, mime)
    check = False
    for item in info_all:
        if uploaded_mime in item["mime"]:
            if uploaded_extension in item["extension"]:
                check = True

    if not check:
        raise Exception('File signature did not match mime, type, or extension.')
    

def acceptable_file(uploaded_file, allowed_types: list = [], allowed_mimes: list = [], allowed_extensions: list = [], allowed_size: int = 100000, regex: str = None):
    '''

    Runs through all the file validation tests.

    Parameters
    ----------

    uploaded_file : <class 'django.core.files.uploadedfile.TemporaryUploadedFile'>
        A model with FileField.

    allowed_types : list (of str)
        The file types that the file is validated against.
        str format : "type" (["type1", "type2", ...])

    allowed_mimes : list (of str)
        The file mime types that the file is validated against.
        str format "type/subtype" 
   
    allowed_extensions : list (of str)
        The file extensions that the file is validated against. 
        str format : "ext1" (without periods ("."); ["ext1", "ext2", ...] not [".ext1", ".ext2", ...])
        Keep in mind that certain operating systems are case sensitve (Linux) while others are case insensitve (Windows) in regards to extensions.
        Because of OS differences, it is your responsibility to provide the correct casing in the extension list.

    allowed_size : int
        The maximum file size that the file is validated against.    

    regex : str, optional
        A string to ensure the file name is not malicious. 
        The string should not include the extensions as this function will add that in.

    Methods
    -------

    virus_test(uploaded_file)
        Tests if a file is a known virus.
    
    regex_file_name_test(uploaded_file, allowed_extensions=allowed_extensions, regex=regex)
        Test to check if the file name is acceptable.

    file_type_test(uploaded_file, allowed_types=allowed_types, allowed_mimes=allowed_mimes, allowed_extensions=allowed_extensions, allowed_size=allowed_size)
        Test to check if the file signature matches all the other attributes of the title. 

        
    '''

    virus_test(uploaded_file)
    regex_file_name_test(uploaded_file, allowed_extensions=allowed_extensions, regex=regex)
    file_type_test(uploaded_file, allowed_types=allowed_types, allowed_mimes=allowed_mimes, allowed_extensions=allowed_extensions, allowed_size=allowed_size)
