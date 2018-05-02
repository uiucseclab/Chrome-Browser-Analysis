I did a forensics analysis of the browser Google Chrome.

I started this project by trying to write a volatility plugin to extract
relevant artifacts from a memory image of a system running chrome. This turned
out to be extremely difficult. I made some progress but I eventually gave up. In
that sense I "wasted" well over half my available time on this project learning
about memory forensics and volatility. However, I did learn a lot throughout this
project and I will present some of what I learned in this document. After I
pivoted away from volatility I wrote 2 tools that collects forensically
interesting artifacts from disk. You can run both tools on any system that chrome
runs on. One will display in an interactive table of information pertaining to
History, Search History, Cookies, Downloads, Autofill, Autofill Profiles, and
Credit Cards. The other tool goes through Chrome's cache and extracts every file
and the corresponding HTTP header.

# Volatility
Despite not having any code to show off for an in-memory analysis I still
learned a lot and put a lot of time into it.

Chrome keeps most of it's relevant data in SQLite databases. It loads these
databases into memory while chrome is in use and saves them to disk
periodically. SQLite is extremely fast and has some unique advantages in a
desktop application. An entire database can be contained in RAM or in a single
file. Unlike other SQL databases in which a server must be running.

SQLite databases do not have any known consistent start or end byte pattern that
would allow one to carve them out of a memory image. So other more complicated
techniques have to be used.

Before I could write a volatility plugin however I had to get a valid memory
image. I tried installing Ubuntu or Windows 10 in a Qemu/KVM box and dumping the
memory but despite everything I tried volatility would not recognize the image.
Eventually I downloaded a Windows 10 Virtualbox Appliance from Microsoft and
used that. Volatility recognized the memory dumps produced by the command line
utility `VBoxManage debugvm "MSEdge - Win10" dumpvmcore --filename ./windows.ram`.

Volatility is not very well documented so I had to learn how it works mostly by
reading code. I spent many hours reading the source code of Volatility and of
other third party plugins. The approach that ended up working for me was to
define a Scanner to search through the physical memory.

```python
class ChromeScanner(scan.BaseScanner):
    checks = []

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles': needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset
```

Then you would use this by passing in an array of byte patterns you'd like to
search for as needles. Then you can iterate over `scan` to get every address in
RAM that matches one of the needles.

Now comes the difficult part. Figuring out what to search for in needles. Like I
said earlier Chrome uses SQLite databases which do not have consistent start and
end bytes for scraping. Instead patterns in SQLite's memory layout have to be
used. Chrome stores history information in the database `History` and the table
`urls`. I will use this table as an example for how to scrape the relevant data
out of memory. The `urls` table is defined as

```
CREATE TABLE urls(id INTEGER
PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER
DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time
INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL)
```

The layout in memory of a SQLite database is documented in detail
[here](https://www.sqlite.org/fileformat.html#varint_format). It's very
complicated and has a lot of detail though so I will summarize here.

SQLite databases are divided into pages. Each page is a fixed size which is
stored in a 16-bit integer field in the database header. Most of a SQLite
database are B-trees, each of which consists of one or more B-tree pages. Each
B-tree page is either a leaf or an internal node. Leaf pages have an 8 byte
header and internal node pages have a 12 byte header.

Each page has a *cell content area* near the end of the page where the B-tree
pages are stored. This is where the SQL records are stored. The first cell
(which contains a B-tree page) to be written is stored at the end of the SQLite
page. Each subsequent cell is stored backwards from there. Finally, after the
B-tree page header is a Cell pointer array which points to each cell. The number
of cells and their location within the database is stored within the B-Tree page
header at known offsets.

Each cell has 4 areas of interest: the *Length of Payload*, the *Row ID*, the *Payload
Header*, and the *Payload*. The *Payload* contains the data that makes up the SQLite
records. The data is serialized and stored concatenated together. The *Payload
Header* stores the details about how to identify each field in the concatenated
data. The *Row ID* and *Length of Payload* are stored using variable length
integers, known as varints. Varints are detailed in the link I gave above and I
won't go into their format.

The most relevant part of this cell for memory forensics is the *Payload
Header*. This is where we can find some bytes to search for. The *Payload
header* has a *Payload Header Length* followed by one or more *Serial Type
Codes*. The *Serial Type Codes* describe what types of fields are in the record
and allows us to find each piece of information. This table is super important:

| Serial Type | Content Size | Meaning |
| ----------- | ------------ | ------- |
| 0 | 0 | NULL |
| 1 | 1 | 8-bit twos-complement-integer |
| 2 | 2 | Big-endian 16-bit twos-complement integer |
| 3 | 3 | Big-endian 24-bit twos-complement integer |
| 4 | 4 | Big-endian 32-bit twos-complement integer |
| 5 | 6 | Big-endian 48-bit twos-complement integer |
| 6 | 8 | Big-endian 64-bit twos-complement integer |
| 7 | 8 | Big-endian IEEE 754-2008 64-bit floating point number |
| 8 | 0 | Integer constant 0. Only available for schema format 4 and higher. |
| 9 | 0 | Integer constant 1. Only available for schema format 4 and higher. |
| 10,11 |  | *Not used. Reserved for expansion.* |
| N >= 12 and even | (N-12)/2 | A BLOB that is (N-12)/2 bytes in length. |
| N >= 13 and odd | (N-13)/2 | A string in the database encoding and (N-13)/2 bytes in length. The nul terminator is omitted. |

Knowing how the Header is layed out and knowing that the header is back to back
with the Payload allows us to construct needles for searching for `url` records.
The `hidden` field will default to 0 meaning that for newer versions of google
chrome will be Serial Type 8 and in older versions of chrome you'll find
`'\x01\x01'` preceding the payload. We can then set the needles to search for this:

```python
class ChromeHistory(common.AbstractWindowsCommand):
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        addr_space = utils.load_as(self._config, astype='physical')
        scanner = ChromeScanner(needles=['\x08http',
                                         '\x01\x01http',
                                         '\x08file',
                                         '\x01\x01file',
                                         '\x08ftp',
                                         '\x01\x01ftp',
                                         '\x08chrome',
                                         '\x01\x01chrome',
                                         '\x08data',
                                         '\x01\x01data',
                                         '\x08about',
                                         '\x01\x01about'])

```

And then look through what the scanner finds.

```python
        for offset in scanner.scan(addr_space):
```

Then you can start parsing the header and scraping the fields out of the
payload. This becomes pretty challenging. This becomes very challenging because
you don't have a good entry location and many fields are variable length. I
eventually gave up on this because it became too challenging. I made some
progress getting fields out of the `url` table but my discoveries here didn't
translate well to other tables. Each one was a ton of work. What finally made me
stop was that I discovered that what was stored in RAM was only briefly
different than what was on disk. Chrome writes changes to these tables to disk
frequently making this extra difficult exercise relatively pointless.

One thing I did try to do before giving up was to find the keys used in a TLS
session in RAM. However, I could not come up with a reliable needle and had
trouble understanding the source code of chrome. I could not find a
datastructure that would lead me to the keys.


# info.py
`info.py` requires python3 and the python packages listed in `requirements.txt`
which can be installed by running `pip install -r requirements.txt`. `info.py`
takes one argument which is the path to chrome's profile directory. Replacing
user with your user account that path can be found:

| Windows | Mac | Linux |
| ------- | --- | ----- |
| C:\Users\user\AppData\Local\Google\Chrome\User Data\Default | /Users/user/Library/Application Support/Google/Chrome/Default | /home/user/.config/google-chrome/Default |

and the script can be launched with `python info.py <chrome_path>`. This script
will serve a web application on localhost port 5000 by default. Going there
gives you an interface to see a ton of forensically interesting artifcats. This
includes all the data available pertaining to the user's history, searches,
cookies, downloads, autfill data, credit cards, and autofill profiles. This
script has only been tested on Ubuntu but should, in theory, work on any OS. If
you can't get it to work try it on Linux.

# cache.py
`cache.py` is run the same way as `info.py` and depends on python3. When ran it
will write to the directory `out` so make sure that is empty. `cache.py` parses
Google Chrome's chache extracting all HTTP headers and cached files. It then
uncompresses the files and writes them along with their HTTP headers into `out`
organized by their mime-type. The disk cache format is very complex so I won't
describe it here. Some of the information can be found in chromium's design
documents:
https://www.chromium.org/developers/design-documents/network-stack/disk-cache
but most was obtained by reading the source code. The most relevant files are
`net/disk_cache/disk_cache.h`, `net/disk_cache/blockfile/disk_format.h`. The
simple rundown is that Chrome stores a hash table in `index` and the data in the
files `data_0`, `data_1`, `data_2`, and `data_3`. Anything that doesn't fit in
there goes in `f_XXXXXX` where `XXXXXX` is a hexadecimal index. Each `f_` file
is an entire cached file. The `data` files contain many smaller cache items with
headers that describe them. This script has only been tested on Ubuntu but
should, in theory, work on any OS. If you can't get it to work try it on Linux.
