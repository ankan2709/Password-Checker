"""
This is a project to create a secure password checker to check if your password has been previously hacked
by someone.
"""

import requests
import hashlib
import sys


def request_api_data(query_characters):
    url = f'https://api.pwnedpasswords.com/range/{query_characters}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error in fetching: {res.status_code}, Please check the API and query characters and try again')
    return res


def get_password_leaks_count(hash_response, hash_to_check):
    hashes = (line.split(':') for line in hash_response.text.splitlines())

    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def check_api_data_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    api_response = request_api_data(first5_char)
    return get_password_leaks_count(api_response, tail)


def main(args):
    for password in args:
        count = check_api_data_password(password)
        if count:
            print(f'{password} was found {count} times. You should probably change your password')
        else:
            print(f'{password} Not Found, you are all set!')
    return 'All done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))