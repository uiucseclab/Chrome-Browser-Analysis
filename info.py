import sys
import sqlite3
import json
from datetime import datetime, timezone, timedelta
import base64
from os.path import join
from flask import Flask, render_template

chrome_dir = sys.argv[1]
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def id_f(x):
    return x

def time_fmt(x):
    if x == 0:
        return 0
    try:
        t = (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=x)).astimezone(tz=None)
        return {
            "display": t.strftime("%c"),
            "timestamp": x
        }
    except:
        return {
            "display": "",
            "timestamp": 0
        }

def b64(x):
    return str(base64.b64encode(x))

def get_sqlite_data(database, query, funcs):
    conn = sqlite3.connect(join(chrome_dir, database))
    c = conn.cursor()
    c.execute(query)
    data = c.fetchall()
    headers = []
    for i, h in enumerate(c.description):
        column = None
        if funcs[i] == time_fmt:
            column = {
                'data': h[0],
                'title': h[0],
                'render': {
                    '_': 'display',
                    'sort': 'timestamp'
                }
            }
        else:
            column = {
                'data': h[0],
                'title': h[0]
            }
        headers.append(column)
    json_data = [headers]
    for d in data:
        json_entry = {}
        for i, f in enumerate(d):
            json_entry[headers[i]['data']] = funcs[i](f)
        json_data.append(json_entry)
    return json.dumps(json_data)

@app.route('/history')
def history():
    return get_sqlite_data('History',
                           'SELECT visits.visit_time, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.hidden FROM urls, visits WHERE urls.id = visits.url;',
                           [time_fmt,                 id_f,     id_f,       id_f,             id_f,             id_f])

@app.route('/searches')
def searches():
    return get_sqlite_data('History',
                           'SELECT visits.visit_time, keyword_search_terms.term, urls.url FROM keyword_search_terms, urls, visits WHERE urls.id = keyword_search_terms.url_id AND urls.id = visits.url',
                           [       time_fmt,          id_f,                      id_f])

@app.route('/cookies')
def cookies():
    return get_sqlite_data('Cookies',
                           'SELECT creation_utc, host_key, name, path, expires_utc, secure, httponly, last_access_utc, has_expires, persistent, priority, encrypted_value, firstpartyonly FROM cookies',
                           [       time_fmt,     id_f,     id_f, id_f, time_fmt,    id_f,   id_f,     time_fmt,        id_f,        id_f,       id_f,     b64,             id_f])

@app.route('/downloads')
def downloads():
    return get_sqlite_data('History',
                           'SELECT guid, target_path, start_time, end_time, received_bytes, total_bytes, last_access_time, referrer, site_url, last_modified, mime_type, original_mime_type, state, danger_type, interrupt_reason, opened, transient, tab_url, tab_referrer_url, etag FROM downloads',
                           [       id_f, id_f,        time_fmt,   time_fmt, id_f,           id_f,        time_fmt,          id_f,     id_f,    time_fmt,      id_f,      id_f,               id_f,  id_f,        id_f,             id_f,   id_f,      id_f,    id_f,             id_f])

@app.route('/autofill')
def autofill():
    return get_sqlite_data('Web Data',
                           'SELECT name, value, date_created, date_last_used, count FROM autofill',
                           [       id_f, id_f,  time_fmt,     time_fmt,       id_f])

@app.route('/credit_cards')
def credit_cards():
    return get_sqlite_data('Web Data',
                           'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified, origin, use_count, use_date, billing_address_id FROM credit_cards',
                           [       id_f,         id_f,             id_f,            b64,                   time_fmt,      id_f,   id_f,      time_fmt, id_f])

@app.route('/autofill_profiles')
def autofill_profiles():
    return get_sqlite_data('Web Data',
                           'SELECT company_name, street_address, dependent_locality, city, state, zipcode, sorting_code, country_code, date_modified, origin, language_code, use_count, use_date FROM autofill_profiles',
                           [       id_f,         id_f,           id_f,               id_f, id_f,  id_f,    id_f,         id_f,         time_fmt,      id_f,   id_f,          id_f,      time_fmt])


if __name__ == '__main__':
    app.run()
