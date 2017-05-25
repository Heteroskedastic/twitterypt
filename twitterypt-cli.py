import argparse

import sys
import traceback

from twitterypt.utils import generate_key_pair, get_twitter_api, TWITTERYPT_PREFIX, make_public_key_long_url, \
    format_public_key, send_to_twitter_account, decrypt_message
from twitterypt.config import cfg


class TwitteryptCLIException(Exception):
    pass


def _input_lines():
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line:
            lines.append(line)
        else:
            break
    return '\n'.join(lines)


def upload_public_key():
    if not cfg.public_key:
        raise TwitteryptCLIException('No public key saved in config! please set you public key by "--set-public-key"'
                                     ' option or "--keys-gen" to generate a pair public/private key')
    twitter_api = get_twitter_api()
    if cfg.twitter_username:
        my_user = twitter_api.GetUser(screen_name=cfg.twitter_username)
    else:
        my_user = twitter_api.VerifyCredentials()
        cfg.update({'twitter_username': my_user.screen_name})
    desc = my_user.description or ''
    idx1 = desc.find(TWITTERYPT_PREFIX)
    if idx1 >= 0:
        idx2 = desc.find('|', idx1 + len(TWITTERYPT_PREFIX))
        idx2 = len(desc) if idx2 < 0 else (idx2 + 1)
        prompt = input('a public key already exists in your profile. do you want to overwrite? [N/y]')
        if prompt not in ('Y', 'y', 'yes'):
            print('Skipped upload public key!')
            return
    else:
        idx1 = idx2 = len(desc)

    print('Step 1: please enter following url in https://goo.gl and enter shorten url in next step:')
    print(make_public_key_long_url(cfg.public_key))
    short_url = input('Step2: Enter goo.gl shorten url here: ')
    formatted_pub_key = format_public_key(short_url)
    new_desc = desc[: idx1] + formatted_pub_key + desc[idx2:]
    twitter_api.UpdateProfile(description=new_desc)
    print('Public key uploaded to your profile!')


def post_twitter_message(screen_name, message=None):
    if message is None:
        print('Enter your message: ')
        message = _input_lines()
    return send_to_twitter_account(message, screen_name)


def download_last_message(count=10):
    count = min(int(count), 200)
    if not cfg.private_key:
        raise TwitteryptCLIException('No private key saved in config! please set you private key by "--set-private-key"'
                                     'option or "--keys-gen" to generate a pair public/private key')
    twitter_api = get_twitter_api()
    messages = twitter_api.GetHomeTimeline(exclude_replies=True, include_entities=False, count=count)
    i = 1
    for message in messages:
        if message.text.startswith(TWITTERYPT_PREFIX):
            try:
                plain_message = decrypt_message(message.text, cfg.private_key).decode()
                print('#{}- at: {} - from: {}'.format(i, message.created_at, message.user.screen_name))
                print(40 * '-')
                print(plain_message)
                print(80 * '=')
                i += 1
            except Exception:
                pass
    if i == 1:
        print('No Recent Message!')

commands = {
    'upload_public_key': upload_public_key,
    'post_twitter_message': post_twitter_message,
    'download_last_message': download_last_message,
}


def twitter_config():
    keys = ['twitter_username', 'twitter_consumer_key', 'twitter_consumer_secret', 'twitter_access_token_key',
            'twitter_access_token_secret', ]
    items = {}
    for k in keys:
        i = input('Enter "{}" (press ENTER to ignore): '.format(k)).strip()
        if i:
            items[k] = i
    if items:
        cfg.update(items)
        print('twitter configs updated!')
    else:
        print('no config updated!')


def keys_gen():
    confirm = True
    if cfg.public_key or cfg.private_key:
        confirm = False
        prompt = 'n'
        try:
            prompt = input('A pair key already exists. do you want to overwrite? [N/y]')
        except KeyboardInterrupt:
            print('Canceled!')
        if prompt in ('Y', 'y', 'yes'):
            confirm = True
    if confirm:
        private_key, public_key = generate_key_pair()
        cfg.update({'private_key': private_key.decode(), 'public_key': public_key.decode()})
        print('New public/private key generated!')


def set_private_key():
    print('Please enter your RSA private key:')
    key = _input_lines()
    cfg.update({'private_key': key})
    print('private key update!')


def set_public_key():
    print('Please enter your RSA public key:')
    key = _input_lines()
    cfg.update({'public_key': key})
    print('public key update!')


def show_configs():
    print ('["{}" Config] Last updated at: {}'.format(cfg.name, cfg.last_update))
    print(80 * '=')
    for k in sorted(cfg.configs.keys()):
        if k in ('name', 'last_update'):
            continue
        v = cfg.configs[k]
        print('{} = {}'.format(k, v))
        print(80 * '-')


def commands_list():
    print('Valid commands: {}'.format(list(commands.keys())))


def process_command(command, args):
    if command not in commands:
        raise TwitteryptCLIException('Invalid command [{}]'.format(command))
    try:
        return commands[command](*args)
    except TypeError:
        raise TwitteryptCLIException('command [{}]: Invalid options {}'.format(command, args))


def main():
    parser = argparse.ArgumentParser(description='Twitterypt CLI.')
    parser.add_argument('command', type=str, nargs='?', help='valid commands are: {}'.format(list(commands.keys())))
    parser.add_argument('options', type=str, nargs='*', help='command options')
    parser.add_argument('--twitter-config', dest='twitter_config', action='store_true',
help='Configure twitter credentials')
    parser.add_argument('--set-private-key', dest='set_private_key', action='store_true',
                        help='set private key manually')
    parser.add_argument('--set-public-key', dest='set_public_key', action='store_true',
                        help='set public key manually')
    parser.add_argument('--keys-gen', dest='keys_gen', action='store_true',
                        help='generate private/public keys automatically')
    parser.add_argument('--show-configs', dest='show_configs', action='store_true',
                        help='print all configs')
    parser.add_argument('--commands-list', dest='commands_list', action='store_true',
                        help='show list of valid commands')

    args = parser.parse_args()
    no_action = True
    if args.command:
        no_action = False
        process_command(args.command, args.options)
    else:
        if args.twitter_config:
            no_action = False
            twitter_config()
        if args.keys_gen:
            no_action = False
            keys_gen()
        if args.set_private_key:
            no_action = False
            set_private_key()
        if args.set_public_key:
            no_action = False
            set_public_key()
        if args.show_configs:
            no_action = False
            show_configs()
        if args.commands_list:
            no_action = False
            commands_list()

    if no_action:
        print(parser.format_help())


if __name__ == '__main__':
    try:
        main()
    except TwitteryptCLIException as e:
        print(e.args and e.args[0])
        sys.exit(1)
    except KeyboardInterrupt:
        print('Canceled!')
        sys.exit(2)
    except Exception as e:
        print('Unexpected Exception:')
        traceback.print_exc()
        sys.exit(3)
