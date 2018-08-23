#!/usr/bin/env python

# Copyright (c) 2016, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>


"""Palo Alto Networks dynamic content update downloader

Downloads the latest content packs from paloaltonetworks.com.

This software is provided without support, warranty, or guarantee.
Use at your own risk.

Works with python 2.7 only.
"""

from __future__ import print_function
import os
import sys
import re
import cookielib
import logging
import ConfigParser
import argparse
import json
from datetime import datetime

import mechanize
import requests

# Optional: Disable insecure platform warnings
#import requests.packages.urllib3
#requests.packages.urllib3.disable_warnings()

class LoginError(StandardError):
    pass

class GetLinkError(StandardError):
    pass

class UnknownPackage(StandardError):
    pass


class ContentDownloader(object):
    """Checks for new content packages and downloads the latest"""

    """This PACKAGE variable can be modified to reflect any changes in the URL's or
    to add additional packages as they come available. It is a basic python
    dictionary where the key is the string usually passed as a command line
    argument to specify a package, and the value is the part of the file download
    URL between the hostname and the package version. For example, a download URL
    takes the form:

        https://downloads.paloaltonetworks.com/content/panupv2-all-contents-578-2874

    The value in the PACKAGE dict should be the part between the
    'downloads.paloaltonetworks.com/' and the '-578-2874' (the version).

    Maintenance of this script involves keeping these values up-to-date with the actual
    URL to download the file.
    """
    PACKAGE_KEY = {
        "appthreat":  "CONTENTS",
        "app":        "APPS",
        "antivirus":  "VIRUS",
        "wildfire":   "WILDFIRE_OLDER",
        "wildfire2":  "WILDFIRE_NEWEST",
        "wf500":      "WF-500 CONTENT",
        "traps":      "TRAPS3.4",
        "clientless": "GPCONTENTS",
    }
    LOGIN_URL = "https://identity.paloaltonetworks.com/idp/startSSO.ping?PartnerSpId=supportCSP&TargetResource=https://support.paloaltonetworks.com/Updates/DynamicUpdates/245"
    UPDATE_URL = "https://support.paloaltonetworks.com/Updates/DynamicUpdates/245"
    GET_LINK_URL = "https://support.paloaltonetworks.com/Updates/GetDownloadUrl"

    def __init__(self, username, password, package="appthreat", debug=False):
        if package is None:
            package = "appthreat"
        if package not in self.PACKAGE_KEY:
            raise UnknownPackage("Unknown package type: %s" % package)
        self.username = username
        self.password = password
        self.package = package
        self.key = self.PACKAGE_KEY[package]
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
        self.browser.open(self.LOGIN_URL)
        self.browser.select_form(nr=0)
        self.browser.form['Email'] = self.username
        self.browser.form['Password'] = self.password
        self.browser.submit()
        # This has resulted in an error page
        if self.browser.response().read().find("The user name or password provided is incorrect.") != -1:
            raise LoginError("Username or password is incorrect")
        if self.browser.response().read().find(
                "Since your browser does not support JavaScript,"
                " you must press the Resume button once to proceed."
        ) == -1: # Getting this message is good
            raise LoginError("Failed to login")
        # No Javascript, so have to submit the "Resume form"
        self.browser.open(self.UPDATE_URL)
        self.browser.select_form(nr=0)
        self.browser.submit()
        html = self.browser.response().read()
        # Save login cookie
        self._save_cookies()

    def check(self):
        logging.info("Checking for new content updates: %s" % self.package)
        result = self._check()
        needlogin = False
        if result.find("<h1>Single Sign On</h1>") != -1:
            needlogin = True
            logging.debug("Got single sign on page")
        elif result.find("<h4>You are not authorized to perform this action.</h4>") != -1:
            needlogin = True
            logging.debug("Got not authorized page")
        elif result.find('webData.pageName = "support:portal:Unauth Home"') != -1:
            needlogin = True
            logging.debug("Got unauth screen")
        elif result.find('<img src="/assets/img/pan-loading.gif" alt="Loading"/>') != -1:
            needlogin = True
            logging.debug("Got loading screen")
        if needlogin:
            logging.info("Not logged in.")
            self.login()
            logging.info("Checking for new content updates (2nd attempt)")
            result = self._check()
        # Grab the __RequestVerificationToken
        self.browser.select_form(nr=0)
        token = self.browser.form['__RequestVerificationToken']
        match = re.search(r'"data":({"Data":.*?"Total":\d+,"AggregateResults":null})', result)
        updates = json.loads(match.group(1))
        return token, updates['Data']

    def _check(self):
        self.browser.open(self.UPDATE_URL)
        return self.browser.response().read()

    def find_latest_update(self, updates):
        updates_of_type = [u for u in updates if u['Key'] == self.key]
        updates_sorted = sorted(updates_of_type, key=lambda x: datetime.strptime(x['ReleaseDate'], '%Y-%m-%dT%H:%M:%S'))
        latest = updates_sorted[-1]
        logging.info("Found latest update:  {0}  Released {1}".format(latest['FileName'], latest['ReleaseDate']))
        return latest['FileName'], latest['FolderName'], latest['VersionNumber']

    def get_download_link(self, token, filename, foldername):
        headers = {'Content-Type': 'application/json; charset=UTF-8',
                   'Accept': 'application/json, text/javascript, */*; q=0.01',
                   'X-Requested-With': 'XMLHttpRequest',
                   }
        payload = {'__RequestVerificationToken': token,
                   'FileName': filename,
                   'FolderName': foldername,
                   }
        response = requests.post(self.GET_LINK_URL, json=payload, headers=headers).json()
        if 'Success' not in response or not response['Success']:
            raise GetLinkError("Failure getting download link: {0}".format(response))
        return response['DownloadUrl']

    def download(self, download_dir, url, filename):
        os.chdir(download_dir)
        self.browser.retrieve(url, filename)
        return filename

    def _save_cookies(self):
        self.cj.save("cookies.txt", ignore_discard=True, ignore_expires=True)


def get_config(filename):
    config = ConfigParser.SafeConfigParser({"filedir": ""})
    config.read(filename)
    username = config.get('config', 'username')
    password = config.get('config', 'password', raw=True)
    download_dir = config.get('config', 'filedir')
    if download_dir == "":
        download_dir = os.getcwd()
    return username, password, download_dir


def parse_arguments():
    parser = argparse.ArgumentParser(description='Download the latest Palo Alto Networks dynamic content update')
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-p', '--package', help="Options: appthreat, app, antivirus, wildfire (for PAN-OS 7.0 and"
                                                " lower), or wildfire2 (for PAN-OS 7.1 and higher), wf500, traps,"
                                                " clientless. If ommited, defaults to 'appthreat'.")
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

    # Create contentdownloader object
    content_downloader = ContentDownloader(username=username, password=password, package=options.package, debug=debugenabled)

    # Check latest version. Login if necessary.
    token, updates = content_downloader.check()

    # Determine latest update
    filename, foldername, latestversion = content_downloader.find_latest_update(updates)

    # Get previously downloaded versions from download directory
    downloaded_versions = []
    for f in os.listdir(download_dir):
        downloaded_versions.append(f)

    # Check if already downloaded latest and do nothing
    if filename in downloaded_versions:
        logging.info("Already downloaded latest version: {0}".format(filename))
        sys.exit(0)

    # Get download URL
    fileurl = content_downloader.get_download_link(token, filename, foldername)

    # Download latest version to download directory
    logging.info("Downloading latest version: %s" % latestversion)
    filename = content_downloader.download(download_dir, fileurl, filename)
    if filename is not None:
        logging.info("Finished downloading file: %s" % filename)
    else:
        logging.error("Unable to download latest content update")


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()
