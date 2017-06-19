import random
import string
import base64
import requests
import twitter
try:
    # python 3
    from urllib.parse import urlencode, urlparse, parse_qs
except ImportError:
    # python 2
    from urllib import urlencode
    from urlparse import urlparse, parse_qs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from twitterypt.config import cfg

#echo "CYPHER_MESSAGE" |openssl base64 -d -A | openssl rsautl -decrypt -oaep -inkey private.pem

LONG_BASE_URL = 'http://mock.co/'
TWITTERYPT_PREFIX = '|EnCt|'
PUBLIC_KEY_BEGIN = '-----BEGIN PUBLIC KEY-----'
PUBLIC_KEY_END = '-----END PUBLIC KEY-----'
PRIVATE_KEY_BEGIN = '-----BEGIN RSA PRIVATE KEY-----'
PRIVATE_KEY_END = '-----END RSA PRIVATE KEY-----'

RSA_HASH_ALGO = hashes.SHA1()
RSA_PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=RSA_HASH_ALGO), algorithm=RSA_HASH_ALGO, label=None)


# public_key = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDuivvGASfW5febaZOM43Px47pI\nPQ3cpq+c68D4gef8G+KgG3mgAXzlWKGtggwykqZRuikDZjHUDmcyphdhNVX50RSQ\n1VN8w6ldryS/DJgx3KsJu3u1cyZDtO1N/07ci3V53qBeNGaZx4N/UhH5Ug7hspIg\nMCYlFAjxwPusoC+s/wIDAQAB\n-----END PUBLIC KEY-----'
# private_key = '-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDuivvGASfW5febaZOM43Px47pIPQ3cpq+c68D4gef8G+KgG3mg\nAXzlWKGtggwykqZRuikDZjHUDmcyphdhNVX50RSQ1VN8w6ldryS/DJgx3KsJu3u1\ncyZDtO1N/07ci3V53qBeNGaZx4N/UhH5Ug7hspIgMCYlFAjxwPusoC+s/wIDAQAB\nAoGAMMyP6xbLbqQG/m0fuT/CtWZP8n1C+7PB00lLZcs1iRavSu+z9u62/Tgfgx5K\nnoHvsmJyB3b9lJMJu4vM1p8Roi9e733HStSkyyv9w0Dkx4MmaZ+5lskhRRbSsFP/\nfCc1wXDJVINXFptg+mmiqF38p6u4wtdpD5rkE+diSmuO2OkCQQDuki227aUmGDcR\nYuH1DLj+OcXZ4TuzGC4ewnXHsj2gOdddPAi34qVJ3xStY2ZOH/PVspi2CW+ELy96\nYd6tgYnLAkEA//hHfpS6ChGy1M7X3dwU1Yu8BXCSjzDtd57SXHe/FHDM8THSwKvd\nEm8+C8Cx5eDORfYH50IYkV16CE+RnLsTHQJBAJzuX0/jhy1F5IN1TjmJwu7IRhOK\ni2DF2SC2vg88ejk5kydrZDjByASNz+Y2aoedkSHTN40XK9oBx/NzCa2Mdn0CQQDw\nD9I9jQ7N0rt9imA52uZPQLYeA+3wDVspDPMNdeDnMsOCkc+uk4DKgToXm6k8hxHt\n20ieQwb3jkuc78MI0wqhAkEAhDBJgtMt1j2inW58P8qXyJsknwqPYds0g3PA413K\njeGAyqfjvIZS5pKbQUH55tPm/kbyHe14j//mkaxvzF4wGg==\n-----END RSA PRIVATE KEY-----'
# profile = 'Hi I am pprolancer! This is my twitterypt info: |EnCt|https://goo.gl/Yu5iqi|'
# profile = 'Hi I am pprolancer! This is my twitterypt info: |EnCt| http://mock.co/?key=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDuivvGASfW5febaZOM43Px47pI%0APQ3cpq%2Bc68D4gef8G%2BKgG3mgAXzlWKGtggwykqZRuikDZjHUDmcyphdhNVX50RSQ%0A1VN8w6ldryS%2FDJgx3KsJu3u1cyZDtO1N%2F07ci3V53qBeNGaZx4N%2FUhH5Ug7hspIg%0AMCYlFAjxwPusoC%2Bs%2FwIDAQAB|'


class TwitteryptException(Exception):
    pass


class InvalidFormatException(TwitteryptException):
    pass


class InvalidUrlException(TwitteryptException):
    pass


class InvalidUrlParameterException(TwitteryptException):
    pass


def rand_str(n):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join([random.choice(chars) for _ in range(n)])


def get_redirected_url(url, level=1):
    location = None
    for i in range(level):
        res = requests.head(url)
        l = res.headers.get('location')
        if not l:
            break
        location = url = l
    return location


def calc_rsa_encrypted_data_length(key):
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise TypeError("key must be an RSA public or private key")
    return (key.key_size + 6) >> 3


def calc_rsa_max_messsage_length(key, hash_algorithm):
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise TypeError("key must be an RSA public or private key")

    max_lenth = calc_rsa_encrypted_data_length(key)
    if hash_algorithm:
        max_lenth = max_lenth - 2 * hash_algorithm.digest_size - 2
    assert max_lenth >= 0
    return max_lenth


def generate_key_pair(as_base64=True, key_size=1024):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    if as_base64:
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return (private_key, public_key)


def make_public_key_long_url(public_key, base_url=LONG_BASE_URL):
    if isinstance(public_key, bytes):
        public_key = public_key.decode()
    key = '\n'.join([l for l in public_key.split('\n') if not l.startswith('-----')])
    args = urlencode({'key': key})
    return '{}?{}'.format(base_url, args)


def encrypt(message, public_key, as_base64=True, _padding=RSA_PADDING):
    if isinstance(message, str):
        message = message.encode()
    if isinstance(public_key, str):
        public_key = public_key.encode()
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())

    enc_data = b''
    chunk = calc_rsa_max_messsage_length(public_key, getattr(_padding, '_algorithm', None))
    enc_data_length = calc_rsa_encrypted_data_length(public_key)
    for i in range(0, len(message), chunk):
        part = message[i: i+chunk]
        enc_part = public_key.encrypt(part, _padding)
        # enc_data += enc_part
        enc_data += ((enc_data_length - len(enc_part)) * b'\x00' + enc_part)
    return base64.b64encode(enc_data) if as_base64 else enc_data


def decrypt(message, private_key, is_base64=True, _padding=RSA_PADDING):
    if isinstance(private_key, str):
        private_key = private_key.encode()
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    if is_base64:
        message = base64.b64decode(message)

    dec_data = b''
    chunk = calc_rsa_encrypted_data_length(private_key)
    for i in range(0, len(message), chunk):
        part = message[i: i+chunk]
        dec_part = private_key.decrypt(part, _padding)
        dec_data += (dec_part)
    return dec_data


def make_encrypted_message_long_url(message, public_key, base_url=LONG_BASE_URL):
    enc_data = encrypt(message, public_key)
    args = urlencode({'data': enc_data})
    return '{}?{}'.format(base_url, args)


def format_public_key(short_url, prefix=TWITTERYPT_PREFIX):
    return '{} {}|'.format(prefix, short_url)


def extract_public_key_from_url(url, arg_name='key', is_shorten=True):
    long_url = url
    if is_shorten:
        long_url = get_redirected_url(url, level=2)
    if not long_url:
        raise InvalidUrlException('Invalid url: {}'.format(url))
    up = urlparse(long_url)
    query = parse_qs(up.query)
    key = query.get(arg_name)
    if not key:
        raise InvalidUrlParameterException('Invalid param: {}'.format(up.query))
    return key[0]


def extract_public_key_from_profile(s, prefix=TWITTERYPT_PREFIX):
    idx1 = s.find(prefix)
    url = None
    if idx1 >= 0:
        idx1 = idx1 + len(prefix)
        idx2 = s.find('|', idx1)
        if idx2 >= 0:
            url = s[idx1: idx2].lstrip()
    if not url:
        raise InvalidFormatException('data format is invalid: {}'.format(s))
    key = extract_public_key_from_url(url)
    return '{}\n{}\n{}'.format(PUBLIC_KEY_BEGIN, key, PUBLIC_KEY_END)


def extract_encrypted_message_from_url(url, arg_name='data', is_shorten=True, as_base64=True):
    long_url = url
    if is_shorten:
        long_url = get_redirected_url(url)
    if not long_url:
        raise InvalidUrlException('Invalid url: {}'.format(url))
    up = urlparse(long_url)
    query = parse_qs(up.query)
    data = query.get(arg_name)
    if not data:
        raise InvalidUrlParameterException('Invalid param: {}'.format(up.query))

    if as_base64:
        data = base64.b64decode(data[0])
    else:
        data = data[0]
    return data


def decrypt_message(message, private_key, prefix=TWITTERYPT_PREFIX):
    idx1 = message.find(prefix)
    url = None
    if idx1 >= 0:
        idx1 = idx1 + len(prefix)
        idx2 = message.find('|', idx1)
        if idx2 >= 0:
            url = message[idx1: idx2].lstrip()
    if not url:
        raise InvalidFormatException('data format is invalid: {}'.format(message))
    enc_data = extract_encrypted_message_from_url(url)
    return decrypt(enc_data, private_key, is_base64=False)


def encrypt_message(message, public_key, prefix=TWITTERYPT_PREFIX, base_url=LONG_BASE_URL):
    url = make_encrypted_message_long_url(message, public_key=public_key, base_url=base_url)
    return '{} {}|'.format(prefix, url)


def get_twitter_api(consumer_key=None, consumer_secret=None, access_token_key=None, access_token_secret=None):
    consumer_key = consumer_key or cfg.twitter_consumer_key
    consumer_secret = consumer_secret or cfg.twitter_consumer_secret
    access_token_key = access_token_key or cfg.twitter_access_token_key
    access_token_secret = access_token_secret or cfg.twitter_access_token_secret
    api = twitter.Api(consumer_key=consumer_key, consumer_secret=consumer_secret, access_token_key=access_token_key,
                      access_token_secret=access_token_secret)
    return api


def post_twitter_message(message, public_key, twitter_api=None):
    twitter_api = twitter_api or get_twitter_api()
    enc = encrypt_message(message, public_key)
    return twitter_api.PostUpdate(enc)


def send_to_twitter_account(message, screen_name=None, user_id=None, twitter_api=None):
    user_args = {}
    if screen_name:
        user_args['screen_name'] = screen_name
    else:
        user_args['user_id'] = user_id
    twitter_api = twitter_api or get_twitter_api()
    user = twitter_api.GetUser(**user_args)
    public_key = extract_public_key_from_profile(user.description)
    return post_twitter_message(message, public_key, twitter_api=twitter_api)
