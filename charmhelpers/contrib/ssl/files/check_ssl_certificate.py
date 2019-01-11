#!/usr/bin/env python3
"""
Nagios check, to check the expiry date of an x509 certificate

Copyright (C) 2019 Canonical, Ltd.
Authors:
    Xav Paice <xav.paice@canonical.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranties of
MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import argparse
import subprocess

STATUS_OK = 0
STATUS_WARN = 1
STATUS_CRIT = 2
STATUS_UNKNOWN = 3


def check_cert_expiry(cert_filename, warn, crit):
    """
    Check the x509 certificate file supplied at path cert_filename for expiry
    dates.  If it expires less than warn seconds, return warning.  If it expires
    less than crit seconds, return crit.  Return unknown on errors.  Return OK
    otherwise.

    Returns: integer
    """
    check = x509_checkend(cert_filename, crit * 86400)
    if check['result'] == 1:
        msg = "CRITICAL: Certificate {} due to expire in less than {} days.".format(cert_filename, crit)
        return STATUS_CRIT, msg
    if check['result'] == 2:
        msg = "UNKNOWN: checking certificate {} failed with {}".format(cert_filename, check['message'])
        return STATUS_UNKNOWN, msg
    check = x509_checkend(cert_filename, warn * 86400)
    if check['result'] == 1:
        msg = "WARNING: Certificate {} due to expire in less than {} days.".format(args.cert_filename, warn)
        return STATUS_WARN, msg
    else:
        msg = "OK: Certificate {} has more than {} days before expiry".format(cert_filename, warn)
        return STATUS_OK, msg


def x509_checkend(cert_filename, time):
    """
    Run subprocess to check the cert doesn't expire within the time supplied.

    Return dict with coded result integer, and message, to account for exception
    handling.
    """
    cmd = ["openssl", "x509", "-checkend", str(time), "-in", cert_filename]
    try:
        check = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = check.communicate()
    except Exception as e:
        return {"result": 2, "message": e}
    if check.returncode == 1:
        if not stderr.decode('UTF-8') == '':
            return {"result": 2, "message": stderr.decode('UTF-8')}
        else:
            return {"result": 1}
    else:
        return {"result": 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check swift-storage health')
    parser.add_argument('-f', '--cert', dest='cert_filename', default='6000', type=str,
                        help='Certificate filename to check')
    parser.add_argument('-w', '--warn', dest='warn_days', default=14,
                        type=int, help='Number of days of certificate validity left before warning')
    parser.add_argument('-c', '--crit', dest='crit_days', default=7,
                        type=int, help='Number of days of certificate validity left before critical')
    args = parser.parse_args()

    status, msg = check_cert_expiry(args.cert_filename, args.warn_days, args.crit_days)
    print(msg)
    if status == STATUS_CRIT:
        sys.exit(STATUS_CRIT)
    elif status == STATUS_WARN:
        sys.exit(STATUS_WARN)
    elif status == STATUS_UNKNOWN:
        sys.exit(STATUS_UNKNOWN)
    else:
        sys.exit(0)
