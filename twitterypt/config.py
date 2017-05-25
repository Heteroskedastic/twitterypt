import os
import datetime

import sqlite3


class DBConfig(object):
    MAIN_NAME = 'main'
    def __init__(self, db_path):
        self.db_path = db_path
        self.configs = None
        self.install()

    def install(self, force=False):
        if force:
            os.remove(self.db_path)
        create_tables_query = 'CREATE TABLE if not exists Config(last_update timestamp, name text unique, '\
            'public_key text, private_key text, twitter_username text, twitter_consumer_key text, twitter_consumer_secret text, '\
            'twitter_access_token_key text, twitter_access_token_secret text)'
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(create_tables_query)
        conn.commit()
        conn.close()

    def update(self, data_dict):
        data_dict.update({'last_update': datetime.datetime.utcnow()})
        data_dict.pop('name', None)
        options = []
        values = []
        cols = []
        for k, v in data_dict.items():
            options.append('{}=?'.format(k))
            cols.append(k)
            values.append(v)
        cols.append('name')
        values.append(self.MAIN_NAME)
        options = ', '.join(options)
        qmarks = ', '.join(len(cols) * ['?'])
        cols = ', '.join(cols)
        update_query = 'update Config set {} where name=?'.format(options)
        insert_query = 'insert into Config({}) values ({})'.format(cols, qmarks)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        res = cursor.execute(update_query, tuple(values))
        if not res.rowcount:
            cursor.execute(insert_query, tuple(values))
        conn.commit()
        conn.close()
        self.load_from_db()

    def load_from_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = 'select * from Config where name=?'
        cursor.execute(query, (self.MAIN_NAME,))
        row = cursor.fetchone()
        cols = [col[0] for col in cursor.description]
        if not row:
            row = len(cols) * [None]
        self.configs = dict(zip(cols, row))

    def get(self, cfg):
        if self.configs is None:
            self.load_from_db()
        return self.configs[cfg]

    def __getattr__(self, item):
        if self.configs is None:
            self.load_from_db()
        if item in self.configs:
            return self.configs[item]
        raise AttributeError('Invalid attribute "{}"'.format(item))

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_PATH, 'config.db')

cfg = DBConfig(DB_PATH)
cfg.load_from_db()
