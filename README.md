## Steps to install
1. $ git clone https://github.com/Heteroskedastic/twitterypt
1. $ cd twitterypt
1. $ sudo pip install virtualenv
1. $ virtualenv -p python3 env
1. $ source env/bin/activate
1. $ pip install -r requirements.txt
1. $ python twitterypt-cli.py -h
1. if show help message then steps are OK!

## Steps to setup twitter credentials
1. create your twitter app and generate Access Tokens from here: https://apps.twitter.com/. you need this auth parameters:
    - consumer_key
    - consumer_secret
    - access_token_key
    - access_token_secret
1. $ python twitterypt-cli.py --twitter-config  # this will ask you twitter app credentials

## Steps to create a pair public/private key
1. if you want to generate new public/private keys:
1. $ python twitterypt-cli.py --keys-gen
1. else if you have alread a public/private keys:
1. $ python twitterypt-cli.py --set-private-key
1. $ python twitterypt-cli.py --set-public-key

## Questions:
1. How to upload public key to my profile?
    - $ python twitterypt-cli.py upload_public_key
1. How to post an encrypted message to a user?
    - $ python twitterypt-cli.py post_twitter_message TWITTER_USERNAME [message]
    
    or
    
    - $ python twitterypt-cli.py post_twitter_message TWITTER_USERNAME
1. How to download your latest encrypted messages?
    - $ python twitterypt-cli.py download_last_message [COUNT]
