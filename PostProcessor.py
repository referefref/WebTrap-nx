import codecs
import hashlib
import logging
import os
import re
import shutil
import urllib.parse as urlparse
import mimetypes
from ClonedResourceDetails import ClonedResourceDetails

CLIENT_SIDE_FORENSICS_CODE = """<script src="/session.js"></script>
<script>
	var xhr = new XMLHttpRequest();
	xhr.open("POST", window.location.href + "additional_data", true);
	xhr.setRequestHeader('Content-Type', 'application/json');
	xhr.send(JSON.stringify(session, null, '\t'));
</script>"""

class PostProcessor(object):
    MISSING_MIME_TYPES = {
        'text/javascript' : ".js"
    }
    DEFAULT_FILE_EXTENSION = ".html"
    FILE_PATH_MAX_LEN = 255
    ILLEGAL_WINDOWS_FILE_PATH_CHARS = ['~', '*', '', ':', '<', '>', '|', '?', '"']
    CLOSE_HEAD_TAG = "</head>"

    SERVER_DEFAULT_SERVE_FILE_NAMES = ["index.html", "index.htm"]
    REDIRECTION_URL_PLACE_HOLDER = "$REDIRECTON_URL$"
    REDIRECTION_TEMPLATE_FILE_NAME = "redirect.html"
    CLIENT_SIDE_FORENSICS_SCRIPT_FILE_NAME = "session.js"
    # Templates are looked up next to this file, so the cloner can be run from any directory
    TEMPLATE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))


    def __init__(self, original_url, cloned_resources, output_directory):
        self.logger = logging.getLogger(__name__)

        self.original_url = original_url
        self.cloned_resources = cloned_resources
        self.output_directory = os.path.abspath(output_directory)

        if not os.path.exists(self.output_directory):
            os.mkdir(self.output_directory)
        self._init_mimetypes()

    def _init_mimetypes(self):
        mimetypes.init()
        for missing_mime_type in self.MISSING_MIME_TYPES:
            mimetypes.add_type(missing_mime_type, self.MISSING_MIME_TYPES[missing_mime_type])

    def run(self):
        self._remove_full_path_links()
        self._update_url_query_paths()
        self._add_client_side_forensic()
        self._add_indexfiles_to_directories()
        self._save_resource_to_files()
        self._copy_client_side_forensic_script()

    def _copy_client_side_forensic_script(self):
        # The injected code loads /session.js, so place it in the web root
        destination = os.path.join(self.output_directory, self.CLIENT_SIDE_FORENSICS_SCRIPT_FILE_NAME)
        if not os.path.exists(destination):
            shutil.copyfile(os.path.join(self.TEMPLATE_DIRECTORY,
                                         self.CLIENT_SIDE_FORENSICS_SCRIPT_FILE_NAME), destination)

    def _add_client_side_forensic(self):
        cloned_resource = self.cloned_resources[self.original_url]
        patched_resource_data = \
            self.patch_resource(cloned_resource.resource_data,
                                self.CLOSE_HEAD_TAG,
                                CLIENT_SIDE_FORENSICS_CODE + self.CLOSE_HEAD_TAG)
        self.cloned_resources[self.original_url] = \
            cloned_resource._replace(resource_data=patched_resource_data)

    def _get_resource_file_path(self, cloned_resource):
        return os.path.join(self.output_directory, cloned_resource.get_relative_file_path())

    def _create_resource_file_path(self, cloned_resource):
        directory = self.output_directory
        for part in cloned_resource.get_directory().split("/"):
            directory = os.path.join(directory, part)
            if not os.path.exists(directory):
                os.mkdir(directory)

    def _save_resource_to_files(self):
        for cloned_resource in list(self.cloned_resources.values()):
            self._create_resource_file_path(cloned_resource)

            with open(self._get_resource_file_path(cloned_resource), 'wb') as file_h:
                file_h.write(cloned_resource.resource_data)

    def patch_resources(self, substring, new_substr):
        for resource_path, cloned_resource in list(self.cloned_resources.items()):

            patched_resource_data = self.patch_resource(cloned_resource.resource_data,
                                                        substring,
                                                        new_substr,
                                                        encoding=cloned_resource.charset)
            self.cloned_resources[resource_path] = cloned_resource._replace(
                resource_data=patched_resource_data)

    def patch_resource(self, data, substring, replacement, encoding='utf-8'):
        # In order to patch the data of the resources we decode it to performing the replace
        # and returning it ot it's original encoding
        try:
            codec = codecs.lookup(encoding)
        except LookupError as error:
            self.logger.warning('failed to decode data from web response, ' +
                                error.args[0])
            return data

        try:
            data = codec.decode(data)[0]
        except ValueError as error:
            self.logger.warning(
                "failed to decode data from web response "\
                "(%s) using encoding %s",
                error.__class__.__name__, encoding)
            return data

        return codec.encode(data.replace(substring, replacement))[0]

    def _remove_full_path_links(self):
        # Remove full url path url links from all the resources

        parsed_original_url = urlparse.urlparse(self.original_url)
        hostname_url_path_http = "http://" + parsed_original_url.netloc
        hostname_url_path_https = "https://" + parsed_original_url.netloc

        self.patch_resources(hostname_url_path_http, "")
        self.patch_resources(hostname_url_path_https, "")

    def mimetype_to_file_extension(self, mime_type):
        guessed_file_extension = mimetypes.guess_extension(mime_type)
        return guessed_file_extension if guessed_file_extension else self.DEFAULT_FILE_EXTENSION

    def _compress_file_path(self, input_url_path):
        file_path = input_url_path.lstrip('/')
        full_file_path_len = len(os.path.join(
            self.output_directory, file_path))

        if self.FILE_PATH_MAX_LEN >= full_file_path_len:
            return input_url_path

        # Calculating how many chars we need to reduce from the path
        deviation_in_path = full_file_path_len - self.FILE_PATH_MAX_LEN
        # Adding the size of the hashed path new directory
        deviation_in_path = deviation_in_path + 33

        splitted_file_path = file_path.split("/")
        file_name = splitted_file_path[-1]

        paths_removing = []
        length_removed = 0
        # Calculate the directory names to remove from the path
        for i in range(len(splitted_file_path) - 2, 0, -1):
            paths_removing.append(splitted_file_path[i])
            length_removed += len(splitted_file_path[i])
            if length_removed > deviation_in_path:
                break

        hashed_path = hashlib.md5(''.join(paths_removing).encode('utf-8')).hexdigest()

        remaining_path = splitted_file_path[:(len(paths_removing)+1)*-1]
        remaining_path.append(hashed_path)
        remaining_path.append(file_name)

        return "/" + "/".join(remaining_path)

    def _strip_file_path_from_invalid_characters(self, file_path):
        return ''.join([x for x in file_path if x not in self.ILLEGAL_WINDOWS_FILE_PATH_CHARS])

    def _fix_file_name(self, cloned_resource):
        parsed_resource_url = urlparse.urlparse(cloned_resource.resource_url)
        # Setting a new file extension based on the file's mime type
        new_file_extension = self.mimetype_to_file_extension(
            cloned_resource.mime_type)

        new_file_name = parsed_resource_url.path

        if parsed_resource_url.query != "":
            query_hashed = hashlib.md5(parsed_resource_url.query.encode('utf-8')).hexdigest()
            new_resource_url = new_file_name + "_" + query_hashed + new_file_extension
        else:
            if new_file_name.endswith(new_file_extension):
                new_resource_url = new_file_name
            else:
                new_resource_url = new_file_name + new_file_extension
        return new_resource_url

    def _update_url_query_paths(self):
        substrings_to_replace = []

        for resource_path, cloned_resource in list(self.cloned_resources.items()):
            resource_url = urlparse.urlparse(cloned_resource.resource_url)

            fixed_file_name_and_path = self._fix_file_name(cloned_resource)
            stripped_file_path = self._strip_file_path_from_invalid_characters(
                fixed_file_name_and_path)
            fixed_resource_path = self._compress_file_path(stripped_file_path)

            substring_to_locate = resource_url.path
            if resource_url.query != "":
                escaped_query = resource_url.query.replace("&", "&amp;")
                substring_to_locate = resource_url.path + "?" + escaped_query

            if substring_to_locate != fixed_resource_path:
                self.cloned_resources[resource_path] = cloned_resource._replace(
                    resource_url=fixed_resource_path)

                substrings_to_replace.append(
                    (substring_to_locate, fixed_resource_path))

        # we are sorting the substring to replaces by the len of the substring to locate
        # because we first want to replace the longest string so we won't create a case
        # we will replace it with a shorter one
        substrings_to_replace.sort(key=lambda tup: len(tup[0]), reverse=True)

        for (fullpath_link, replacement) in substrings_to_replace:
            self.patch_resources(fullpath_link, replacement)

        self._update_relative_links_in_cloned_page(substrings_to_replace)

    def _update_relative_links_in_cloned_page(self, substrings_to_replace):
        # The replacements above only find root-relative links ("/js/app.js?v=1").
        # Pages that use links relative to their own directory ("js/app.js?v=1")
        # are fixed here, in the cloned page only, where each link is a whole
        # attribute value (preceded by a quote, "(" or "./" and followed by a quote or ")").
        cloned_page = self.cloned_resources[self.original_url]
        page_directory = urlparse.urlparse(self.original_url).path
        page_directory = page_directory[:page_directory.rfind('/') + 1] or '/'
        try:
            codec = codecs.lookup(cloned_page.charset)
            data = codec.decode(cloned_page.resource_data)[0]
        except (LookupError, ValueError):
            return
        for (fullpath_link, replacement) in substrings_to_replace:
            if not fullpath_link.startswith(page_directory):
                continue
            relative_link = fullpath_link[len(page_directory):]
            if not relative_link:
                continue
            relative_replacement = replacement[len(page_directory):] \
                if replacement.startswith(page_directory) else replacement
            pattern = r'''(?<=["'(])(\./)?''' + re.escape(relative_link) + r'''(?=["')])'''
            data = re.sub(pattern, lambda m: (m.group(1) or '') + relative_replacement, data)
        self.cloned_resources[self.original_url] = cloned_page._replace(
            resource_data=codec.encode(data)[0])

    def _get_directories_without_default_files(self):
        directories = {}
        for cloned_resource in list(self.cloned_resources.values()):
            resource_directory = cloned_resource.get_directory()

            directory = "/"
            directories[directory] = False
            for part in resource_directory.split("/"):
                if part:
                    directory = directory + part +"/"
                directories[directory] = False

        for cloned_resource in list(self.cloned_resources.values()):
            resource_directory = "/" + cloned_resource.get_directory()
            if resource_directory != "/":
                resource_directory += "/"
            if cloned_resource.get_filename() in self.SERVER_DEFAULT_SERVE_FILE_NAMES:
                directories[resource_directory] = True

        return directories

    def _add_indexfiles_to_directories(self):
        # We want to make sure that in any directory that we create there is an index file
        # So we manually create it
        directories = self._get_directories_without_default_files()

        # Setting up the data of the redirection file
        with open(os.path.join(self.TEMPLATE_DIRECTORY, self.REDIRECTION_TEMPLATE_FILE_NAME), "rb") as template_file:
            redirection_file_data = template_file.read()
        dest_redirection_url = "/" + \
            self.cloned_resources[self.original_url].get_relative_file_path()
        redirection_file_data = redirection_file_data.replace(
            self.REDIRECTION_URL_PLACE_HOLDER.encode('utf-8'), dest_redirection_url.encode('utf-8'))

        # Adding default resource for each directory that don't have a default file
        # A default file is a file that an HTTP Server will serve
        # if there is no file in the browsed directory
        for directory, is_default_file_exist in list(directories.items()):
            if is_default_file_exist:
                continue

            resource_url_path = directory + self.SERVER_DEFAULT_SERVE_FILE_NAMES[0]
            redirection_cloned_resource = ClonedResourceDetails(resource=resource_url_path,
                                                                mime_type="text/html",
                                                                resource_data=redirection_file_data,
                                                                resource_url=resource_url_path,
                                                                charset="utf-8",
                                                                query="")
            self.cloned_resources[resource_url_path] = redirection_cloned_resource
