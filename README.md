Palo Alto Networks ContentPack Downloader
=========================================

Checks for the latest content pack and downloads it if needed.

**----=== UPDATE Feb 2018 ===----**  
In January, changes were made to the Palo Alto Networks Support Portal that broke this script. It has now been updated to work with the new Support Portal.

Install
-------

Download the files in this repository.

Install mechanize:

    pip install mechanize
    pip install requests
    
    - or -
    
    easy_install mechanize
    easy_install requests

Configure
---------

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

By default, the script will download the latest *App+Threat* content pack.
Download other packages using the `-p` argument:

    python content_downloader.py -p antivirus

Possible values for `-p` argument:

* appthreat (default)
* app
* antivirus
* wildfire
* wildfire2
* wf500
* traps
* clientless

Note: The *wildfire* package is for PAN-OS 7.0 and lower, the *wildfire2*
package is for PAN-OS 7.1 and higher.

Disclaimer
----------

This script comes with no warranty or guarantee. Use at your own risk.
