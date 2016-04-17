#!/usr/bin/env python

from __future__ import print_function
import os
import sys
import re
import random
import cookielib
import json
import logging
import datetime
import ConfigParser
import argparse
from urllib2 import HTTPError

import mechanize
# Disable insecure platform warnings
#import requests.packages.urllib3
#requests.packages.urllib3.disable_warnings()

class LoginError(StandardError):
    pass

class UpdateError(StandardError):
    pass

class FetchStatusError(StandardError):
    pass

class ContentDownloader(object):

    PREFIX = "panupv2-all-contents"

    SUPPORT_URL = "https://support.paloaltonetworks.com"
    UPDATE_URL = "https://support.paloaltonetworks.com/Updates/DynamicUpdates"

    def __init__(self, username, password, debug=False):
        self.username = username
        self.password = password
        self.latestversion = None
        self.fileurl = None
        self.cj = cookielib.LWPCookieJar()
        try:
            self.cj.load("cookies.txt", ignore_discard=True, ignore_expires=True)
        except IOError:
            # Ignore if there are no cookies to load
            logging.debug("No existing cookies found")
            pass
        self.browser = self.get_browser(debug)

    def get_browser(self, debug=False):
        br = mechanize.Browser()
        # Cookie Jar
        br.set_cookiejar(self.cj)
        # Browser options
        br.set_handle_equiv(True)
        #br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        br.addheaders = [
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"),
        ]
        if debug:
            br.set_debug_http(True)
            br.set_debug_redirects(True)
            br.set_debug_responses(True)
        return br

    def login(self):
        logging.info("Logging in")
        self.browser.open(self.SUPPORT_URL)
        self.browser.select_form(nr=0)
        self.browser.form['Email'] = self.username
        self.browser.form['Password'] = self.password
        self.browser.submit()
        # No Javascript, so have to submit the "Resume form"
        self.browser.select_form(nr=0)
        self.browser.submit()
        html = self.browser.response().read()
        if html.find("Welcome") == -1:
            raise LoginError("Failed to login")
        # Save login cookie
        self._save_cookies()

    def check(self):
        logging.info("Checking for new content updates")
        result = self._check()
        needlogin = False
        if result.find("<h1>Single Sign On</h1>") != -1:
            needlogin = True
            logging.debug("Got single sign on page")
        elif result.find("<h4>You are not authorized to perform this action.</h4>") != -1:
            needlogin = True
            logging.debug("Got not authorized page")
        if needlogin:
            logging.info("Not logged in.")
            self.login()
            logging.info("Checking for new content updates (2nd attempt)")
            result = self._check()
        file_url = "https://downloads.paloaltonetworks.com/content/" + self.PREFIX
        try:
            # Grab the first link, which is the download link for the first dynamic update
            url = list(self.browser.links(url_regex=file_url))[0].url
        except IndexError:
            raise UpdateError("Unable to get content update list")
        file_regex = file_url + "-([\d-]*)\?"
        version = re.search(file_regex, url).group(1)
        self.latestversion = version
        self.fileurl = url
        return version, url

    def _check(self):
        self.browser.open(self.UPDATE_URL)
        return self.browser.response().read()

    def download(self, download_dir):
        if self.latestversion is not None and self.fileurl is not None:
            os.chdir(download_dir)
            filename = self.PREFIX+"-"+self.latestversion
            self.browser.retrieve(self.fileurl, filename)
            return filename

    def _save_cookies(self):
        self.cj.save("cookies.txt", ignore_discard=True, ignore_expires=True)


def get_config(filename):
    config = ConfigParser.SafeConfigParser({"filedir": ""})
    config.read(filename)
    username = config.get('config', 'username')
    password = config.get('config', 'password')
    download_dir = config.get('config', 'filedir')
    if download_dir == "":
        download_dir = os.getcwd()
    return username, password, download_dir


def parse_arguments():
    parser = argparse.ArgumentParser(description='Download the latest Palo Alto Networks dynamic content update')
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    return parser.parse_args()


def enable_logging(options):
    # Logging
    if options.verbose is not None:
        if options.verbose == 1:
            logging_level = logging.INFO
            logging_format = ' %(message)s'
        else:
            logging_level = logging.DEBUG
            logging_format = '%(levelname)s: %(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)
    return True if options.verbose > 1 else False


def main():
    # Parse CLI arguments
    options = parse_arguments()
    # Enable logging
    debugenabled = enable_logging(options)

    # Config file (for support account credentials)
    username, password, download_dir = get_config('content_downloader.conf')

    # Get previously downloaded versions from download directory
    downloaded_versions = []
    for f in os.listdir(download_dir):
        match = re.match(ContentDownloader.PREFIX + "-([\d-]*)$", f)
        if match is not None:
            downloaded_versions.append(match.group(1))

    # Create contentdownloader object and login
    content_downloader = ContentDownloader(username=username, password=password, debug=debugenabled)

    # Check latest version
    latestversion, fileurl = content_downloader.check()

    # Check if already downloaded latest and do nothing
    if latestversion in downloaded_versions:
        logging.info("Already downloaded latest version: %s" % latestversion)
        sys.exit(0)

    # Download latest version to download directory
    logging.info("Downloading latest version: %s" % latestversion)
    filename = content_downloader.download(download_dir)
    if filename is not None:
        logging.info("Finished downloading file: %s" % filename)
    else:
        logging.error("Unable to download latest content update")


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()
