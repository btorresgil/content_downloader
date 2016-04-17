Palo Alto Networks ContentPack Downloader
=========================================

Checks for the latest content pack and downloads it if needed.

Install
-------

Download the files in this repository.

Install mechanize:

    pip install mechanize
    - or -
    easy_install mechanize

Configuration
-------------

Modify content_downloader.conf and fill in the ``username`` and
``password`` arguments with your Palo Alto Networks support
account credentials.

Optionally you can set ``filedir`` to the directory to which the
content packs should be downloaded.

Example content_downloader.conf:

    [config]
    username=me@example.com
    password=p@ssw0rd123
    filedir=/home/myuser/contentpacks

Usage
-----

Run the python file like this:

    python content_downloader.py

You can add -v for verbose, or -vv for extra verbose:

    python content_downloader.py -v

Disclaimer
----------

This script comes with no warranty or guarantee. Use at your own risk.