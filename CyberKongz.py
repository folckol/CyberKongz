import base64
import datetime
import json
import random
import re
import ssl
import imaplib
import email
import time
import traceback
from TwitterModel import *

import capmonster_python
import requests
import cloudscraper
from eth_account.messages import encode_defunct
from web3.auto import w3

def random_user_agent():
    browser_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{2}_{3}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{1}.{2}) Gecko/20100101 Firefox/{1}.{2}',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Edge/{3}.{4}.{5}'
    ]

    chrome_version = random.randint(70, 108)
    firefox_version = random.randint(70, 108)
    safari_version = random.randint(605, 610)
    edge_version = random.randint(15, 99)

    chrome_build = random.randint(1000, 9999)
    firefox_build = random.randint(1, 100)
    safari_build = random.randint(1, 50)
    edge_build = random.randint(1000, 9999)

    browser_choice = random.choice(browser_list)
    user_agent = browser_choice.format(chrome_version, firefox_version, safari_version, edge_version, chrome_build, firefox_build, safari_build, edge_build)

    return user_agent

def get_last_mail(login, password):
    count = 0
    while count < 5:

        # Введите свои данные учетной записи
        email_user = login
        email_pass = password

        if '@rambler' in login or '@lenta' in login or '@autorambler' in login or '@ro' in login:
            # Подключение к серверу IMAP
            mail = imaplib.IMAP4_SSL("imap.rambler.ru")

        else:
            mail = imaplib.IMAP4_SSL("imap.mail.ru")

        mail.login(email_user, email_pass)

        # Выбор почтового ящика
        mail.select("inbox")

        # Поиск писем с определенной темой
        typ, msgnums = mail.search(None, 'SUBJECT "Trove Email Verification"')
        msgnums = msgnums[0].split()

        # Обработка писем
        link = ''

        for num in msgnums:
            typ, data = mail.fetch(num, "(BODY[TEXT])")
            msg = email.message_from_bytes(data[0][1])
            text = msg.get_payload(decode=True).decode()

            # print(text.replace('=\r\n', '').split('<a href=3D"')[1].split('" target=3D"')[0])

            # Поиск ссылки в тексте письма
            link_pattern = r'https://trove-api.treasure.lol/account/verify-email\S*'
            match = re.search(link_pattern, text.replace('=\r\n', '').replace('"', ' '))

            # ('\n\printn')
            if match:
                link = match.group().replace("verify-email?token=3D", "verify-email?token=").replace("&email=3D", "&email=").replace("&redirectUrl=3D", "&redirectUrl=")
                # print(f"Найдена ссылка: \n\n{link}")
            else:
                # print("Ссылка не найдена")
                count += 1
                time.sleep(2)

        # Завершение сессии и выход
        mail.close()
        mail.logout()

        if link != '':
            return link

    return None

class Discord:

    def __init__(self, token, proxy, cap_key):

        self.cap = capmonster_python.HCaptchaTask(cap_key)
        self.token = token
        self.proxy = proxy

        # print(token)
        # print(proxy)
        # print(cap_key)

        self.session = self._make_scraper()
        self.ua = random_user_agent()
        self.session.user_agent = self.ua
        self.session.proxies = self.proxy
        self.super_properties = self.build_xsp(self.ua)


        self.cfruid, self.dcfduid, self.sdcfduid = self.fetch_cookies(self.ua)
        self.fingerprint = self.get_fingerprint()


    def JoinServer(self, invite):

        rer = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token})

        # print(rer.text, rer.status_code)
        # print(rer.text)
        # print(rer.status_code)

        if "200" not in str(rer):
            site = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
            tt = self.cap.create_task("https://discord.com/api/v9/invites/" + invite, site)
            # print(f"Created Captcha Task {tt}")
            captcha = self.cap.join_task_result(tt)
            captcha = captcha["gRecaptchaResponse"]
            # print(f"[+] Solved Captcha ")
            # print(rer.text)

            self.session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive',
                               'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                               'X-Super-Properties': self.super_properties,
                               'Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',
                               "User-Agent": self.ua,
                               'Content-Type': 'application/json', 'Authorization': 'undefined', 'Accept': '*/*',
                               'Origin': 'https://discord.com', 'Sec-Fetch-Site': 'same-origin',
                               'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
                               'Referer': 'https://discord.com/@me', 'X-Debug-Options': 'bugReporterEnabled',
                               'Accept-Encoding': 'gzip, deflate, br',
                               'x-fingerprint': self.fingerprint,
                               'Cookie': f'__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; __cf_bm=DFyh.5fqTsl1JGyPo1ZFMdVTupwgqC18groNZfskp4Y-1672630835-0-Aci0Zz919JihARnJlA6o9q4m5rYoulDy/8BGsdwEUE843qD8gAm4OJsbBD5KKKLTRHhpV0QZybU0MrBBtEx369QIGGjwAEOHg0cLguk2EBkWM0YSTOqE63UXBiP0xqHGmRQ5uJ7hs8TO1Ylj2QlGscA='}
            rej = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}, json={
                "captcha_key": captcha,
                "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
            })
            # print(rej.text())
            # print(rej.status_code)
            if "200" in str(rej):
                return 'Successfully Join 0', self.super_properties
            if "200" not in str(rej):
                return 'Failed Join'

        else:
            with self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}) as response:
                # print(response.text)
                pass
            return 'Successfully Join 1', self.super_properties


    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def build_xsp(self, ua):
        # ua = get_useragent()
        _,fv = self.get_version(ua)
        data = json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": ua,
            "browser_version": fv,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": self.get_buildnumber(),
            "client_event_source": None
        }, separators=(",",":"))
        return base64.b64encode(data.encode()).decode()

    def get_version(self, user_agent):  # Just splits user agent
        chrome_version = user_agent.split("/")[3].split(".")[0]
        full_chrome_version = user_agent.split("/")[3].split(" ")[0]
        return chrome_version, full_chrome_version

    def get_buildnumber(self):  # Todo: make it permanently work
        r = requests.get('https://discord.com/app', headers={'User-Agent': 'Mozilla/5.0'})
        asset = re.findall(r'([a-zA-z0-9]+)\.js', r.text)[-2]
        assetFileRequest = requests.get(f'https://discord.com/assets/{asset}.js',
                                        headers={'User-Agent': 'Mozilla/5.0'}).text
        try:
            build_info_regex = re.compile('buildNumber:"[0-9]+"')
            build_info_strings = build_info_regex.findall(assetFileRequest)[0].replace(' ', '').split(',')
        except:
            # print("[-]: Failed to get build number")
            pass
        dbm = build_info_strings[0].split(':')[-1]
        return int(dbm.replace('"', ""))

    def fetch_cookies(self, ua):
        try:
            url = 'https://discord.com/'
            headers = {'user-agent': ua}
            response = self.session.get(url, headers=headers, proxies=self.proxy)
            cookies = response.cookies.get_dict()
            cfruid = cookies.get("__cfruid")
            dcfduid = cookies.get("__dcfduid")
            sdcfduid = cookies.get("__sdcfduid")
            return cfruid, dcfduid, sdcfduid
        except:
            # print(response.text)
            return 1

    def get_fingerprint(self):
        try:
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', proxies=self.proxy).json()['fingerprint']
            # print(f"[=]: Fetched Fingerprint ({fingerprint[:15]}...)")
            return fingerprint
        except Exception as err:
            # print(err)
            return 1



def register_f(web3, address, private_key, params, authority_signature, id):
    my_address = address
    nonce = web3.eth.get_transaction_count(w3.to_checksum_address(my_address))
    who_swap = w3.to_checksum_address(my_address)

    with open('abi.json') as f:
        abi = json.load(f)

    contract = web3.eth.contract(w3.to_checksum_address('0x072b65f891b1a389539e921bdb9427af41a7b1f7'), abi=abi)

    register = contract.get_function_by_selector("0x95f38e77")
    # print(params)
    params = {
        'name': params[0],
        'discriminant': params[1],
        'owner': who_swap,
        'resolver': w3.to_checksum_address(params[2]),
        'nonce': int(params[3], 16),
    }


    transaction = register(params, authority_signature).build_transaction(
        {
            "chainId": web3.eth.chain_id,
            "gasPrice": web3.eth.gas_price,
            "from": who_swap,
            "value": 0,
            "nonce": nonce,
        }
    )

    signed_txn = web3.eth.account.sign_transaction(
        transaction, private_key=private_key
    )

    raw_tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # print(f'{id} - Transaction signed')
    return web3.to_hex(raw_tx_hash)


class CyberKongz:

    def __init__(self, accs_data, data):

        self.data = data
        self.address = accs_data['address']
        self.private_key = accs_data['private_key']
        self.tw_auth_token = accs_data['tw_auth_token']
        self.tw_csrf = accs_data['tw_csrf']
        # self.mail = accs_data['mail']
        # self.mail_pass = accs_data['mail_pass']

        self.defaultFormatProxy = f"{accs_data['proxy'].split('/')[-1].split('@')[1].split(':')[0]}:{accs_data['proxy'].split('/')[-1].split('@')[1].split(':')[1]}:{accs_data['proxy'].split('/')[-1].split('@')[0].split(':')[0]}:{accs_data['proxy'].split('/')[-1].split('@')[0].split(':')[1]}"

        self.proxy = {'http': accs_data['proxy'], 'https': accs_data['proxy']}

        self.session = self._make_scraper()
        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # self.session.proxies = self.proxy
        self.session.user_agent = random_user_agent()

    def execute_task(self):
        self.Connect_Twitter()
        self.Connect_Wallet()
        status = self.Finish()

        return status


    def Connect_Wallet(self):

        message = encode_defunct(text='Verify your wallet address')
        signed_message = w3.eth.account.sign_message(message, private_key=self.private_key)
        self.signature = signed_message["signature"].hex()


    def Finish(self):

        payload = {"signature":self.signature,
                   "address":self.address,
                   "role":random.choice(self.data['role']),
                   "firstBuyDate":random.choice(["2017","2018","2019","2020","2021","2022","2023"]),
                   "influencerDislike":random.choice(self.data['influencerDislike']),
                   "kongChoice":random.choice(['Eat', 'Split']),
                   "web3State":random.choice(self.data['web3State']),
                   "mintDate":"03/03/2021",
                   "whoIsCoco":random.choice(self.data['whoIsCoco']),
                   "applicationType":"individual"}

        with self.session.post('https://genkai.cyberkongz.com/api/portal', json=payload) as response:
            if response.text == '{"message":"Application sent"}':
                return 'Заход успешно осуществлен'
            else:
                return 'Ошибка'

    def Connect_Twitter(self):

        with self.session.get('https://genkai.cyberkongz.com/api/auth/csrf') as response:
            csrf = response.json()['csrfToken']

        # input()

        payload = {'redirect': False,
                   'callbackUrl': 'https://genkai.cyberkongz.com//?applicationType=individual',
                   'csrfToken': csrf,
                   'json': True}

        self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})

        self.session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})


        with self.session.post('https://genkai.cyberkongz.com/api/auth/signin/twitter?', data=payload, timeout=15, allow_redirects=True) as response:
            # time.sleep(2)
            # print(response.text)
            # print(response.url)

            link = response.url


            redirect_uri = link.split('redirect_uri=')[-1].split('&')[0]
            code_challenge = link.split('code_challenge=')[-1].split('&')[0]
            client_id = link.split('client_id=')[-1].split('&')[0]
            scope = link.split('scope=')[-1].split('&')[0]
            state = link.split('state=')[-1].split('&')[0]

            self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})
            twitter_headers = {
                'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                'x-twitter-auth-type': 'OAuth2Session',
                'x-csrf-token': self.tw_csrf,
                'Content-Type': 'application/x-www-form-urlencoded'}

            # print(self.tw_auth_token, self.tw_csrf)


            with self.session.get(f'https://twitter.com/i/api/2/oauth2/authorize?code_challenge={code_challenge}&code_challenge_method=S256&client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}&state={state}',headers=twitter_headers, timeout=10, allow_redirects=True) as response:

                auth_code = response.json()['auth_code']
                payload = {'approval': 'true',
                           'code': auth_code}

                time.sleep(1)

                with self.session.post(f'https://twitter.com/i/api/2/oauth2/authorize', data=payload, headers=twitter_headers, timeout=15, allow_redirects=True) as response:

                        url = response.json()['redirect_uri']

                        with self.session.get(url, timeout=15) as response:
                            # print(response.text)
                            # print(f'{self.id} - Twitter connected')
                            pass

    def _get_message_to_sign(self, timestamp):

        return 'Hi! Welcome to Tabi.\n\n'\
               'Please sign the message to let us know that you own the wallet.\n\n'\
                'Signing is gas-less and will not give Tabi permission to conduct any transactions with your wallet.\n\n'\
               f'Time stamp is {timestamp}.'

    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )


if __name__ == '__main__':

    twitterCookies_AT = []
    twitterCookies_CT0 = []
    addresses = []
    privates = []
    proxies = []

    q1 = []
    q3 = []
    q5 = []
    q7 = []

    for y in ['1','3','5','7']:
        with open(f'FILEs/Questions/Q{y}.txt', 'r') as file:
            for i in file:
                if y == '1':
                    q1.append(i.rstrip())
                elif y == '3':
                    q3.append(i.rstrip())
                elif y == '5':
                    q5.append(i.rstrip())
                elif y == '7':
                    q7.append(i.rstrip())


    with open('FILEs/Addresses.txt', 'r') as file:
        for i in file:
            addresses.append(i.rstrip())

    with open('FILEs/Proxies.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())

    with open('FILEs/Privates.txt', 'r') as file:
        for i in file:
            privates.append(i.rstrip())

    with open('FILEs/TwitterCookies.txt', 'r') as file:
        for i in file:
            twitterCookies_AT.append(i.rstrip().split('auth_token=')[-1].split(';')[0])
            twitterCookies_CT0.append(i.rstrip().split('ct0=')[-1].split(';')[0])

    for i in range(len(proxies)):

        try:

            result = CyberKongz({'address': addresses[i],
                                 'private_key': privates[i],
                                 'tw_auth_token': twitterCookies_AT[i],
                                 'tw_csrf': twitterCookies_CT0[i],
                                 'proxy': f'http://{proxies[i].split(":")[2]}:{proxies[i].split(":")[3]}@{proxies[i].split(":")[0]}:{proxies[i].split(":")[1]}'}).execute_task()

            print(i, '-', result)

        except KeyError:

            print('В одном из файлов закончились данные')
            break

        except:
            print(i, '- Ошибка')

    input()

    # print(datetime.datetime.utcnow().timestamp())
