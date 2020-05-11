import requests
import hashlib
import sys


def request_api_data(passwd_query):
    '''Rerutns the response of the api if return code is 200'''
    url = 'https://api.pwnedpasswords.com/range/' + passwd_query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error in fetching: {res.status_code}, check the api request")
    return res


def get_password_count(hashes, hash_to_check):
    '''Get the count of hashes got from api response, returns 0 if the testing password's hash didn't match in
    response body's hash '''
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, c in hashes:
        if h == hash_to_check:
            print(f"Hash: {h} \nTail: {hash_to_check}")
            return c
    return 0


def pwned_api_check(password):
    '''Calculates the sha1 has for the given password'''
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} number of times.. change the password")
        else:
            print(f"{password} can be used...")


if __name__ == '__main__':
    main(sys.argv[1:])
