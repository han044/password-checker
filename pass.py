''' Password checker with pwnedpasswords API, User can input password in passwords.txt, more passwords can be entered in the newline, that is the user must
individually write each passkey in a a newline to check for the breach detais. spaces are ignored^ '''
from ast import Raise
import requests
import hashlib
import sys


def getPassBreaches(hashes, pass_tail):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == pass_tail:
            return count

    return 0


def checkAPIRequest(pass_key):
    url = 'https://api.pwnedpasswords.com/range/' + pass_key
    req = requests.get(url)
    if (req.status_code != 200):
        raise RuntimeError("Status Code is Not 200, Ending Process")

    return req


def checkPwnedApi(password):
    sh1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    sha_five, sha_tail = sh1_pass[:5], sh1_pass[5:]
    # stores request value for first 6 matching sha1 password format
    req = checkAPIRequest(sha_five)

    return getPassBreaches(req, sha_tail)


def main():
    with open('passwords.txt', 'r') as pass_file:
        passwords = pass_file.read()
        passwords = passwords.replace(" ", "")  # remove empty spaces
        passwords = passwords.splitlines()  # read password per line

    for pw in passwords:
        c = checkPwnedApi(pw)
        if (c):
            print(f'Password "{pw}" has been breached {c} times')
        else:
            print(f'Password "{pw}" has not been breached')

    return 'Process Complete'


if __name__ == '__main__':
    sys.exit(main())
