import traceback
import sys

MAXREAD = 1048576
CHATTY = 0
IOHDRSZ = 24
PORT = 564

Tversion = 100
Rversion = 101
Tauth = 102
Rauth = 103
Tattach = 104
Rattach = 105
Terror = 106
Rerror = 107
Tflush = 108
Rflush = 109
Twalk = 110
Rwalk = 111
Topen = 112
Ropen = 113
Tcreate = 114
Rcreate = 115
Tread = 116
Rread = 117
Twrite = 118
Rwrite = 119
Tclunk = 120
Rclunk = 121
Tremove = 122
Rremove = 123
Tstat = 124
Rstat = 125
Twstat = 126
Rwstat = 127

cmdName = {Tversion: 'Tversion',
           Rversion: 'Rversion',
           Tauth: 'Tauth',
           Rauth: 'Rauth',
           Tattach: 'Tattach',
           Rattach: 'Rattach',
           Terror: 'Terror',
           Rerror: 'Rerror',
           Tflush: 'Tflush',
           Rflush: 'Rflush',
           Twalk: 'Twalk',
           Rwalk: 'Rwalk',
           Topen: 'Topen',
           Ropen: 'Ropen',
           Tcreate: 'Tcreate',
           Rcreate: 'Rcreate',
           Tread: 'Tread',
           Rread: 'Rread',
           Twrite: 'Twrite',
           Rwrite: 'Rwrite',
           Tclunk: 'Tclunk',
           Rclunk: 'Rclunk',
           Tremove: 'Tremove',
           Rremove: 'Rremove',
           Tstat: 'Tstat',
           Rstat: 'Rstat',
           Twstat: 'Twstat',
           Rwstat: 'Rwstat'}

version = '9P2000'
versionu = '9P2000.u'

Ebadoffset = "bad offset"
Ebotch = "9P protocol botch"
Ecreatenondir = "create in non-directory"
Edupfid = "duplicate fid"
Eduptag = "duplicate tag"
Eisdir = "is a directory"
Enocreate = "create prohibited"
Enoremove = "remove prohibited"
Enostat = "stat prohibited"
Enotfound = "file not found"
Enowstat = "wstat prohibited"
Eperm = "permission denied"
Eunknownfid = "unknown fid"
Ebaddir = "bad directory in wstat"
Ewalknotdir = "walk in non-directory"
Eopen = "file not open"

NOTAG = 0xffff
NOFID = 0xffffffffL

# for completeness including all of p9p's defines
OREAD = 0  # open for read
OWRITE = 1  # write
ORDWR = 2  # read and write
OEXEC = 3  # execute, == read but check execute permission
OTRUNC = 16  # or'ed in (except for exec), truncate file first
OCEXEC = 32  # or'ed in, close on exec
ORCLOSE = 64  # or'ed in, remove on close
ODIRECT = 128  # or'ed in, direct access
ONONBLOCK = 256  # or'ed in, non-blocking call
OEXCL = 0x1000  # or'ed in, exclusive use (create only)
OLOCK = 0x2000  # or'ed in, lock after opening
OAPPEND = 0x4000  # or'ed in, append only

AEXIST = 0  # accessible: exists
AEXEC = 1  # execute access
AWRITE = 2  # write access
AREAD = 4  # read access

# Qid.type
QTDIR = 0x80  # type bit for directories
QTAPPEND = 0x40  # type bit for append only files
QTEXCL = 0x20  # type bit for exclusive use files
QTMOUNT = 0x10  # type bit for mounted channel
QTAUTH = 0x08  # type bit for authentication file
QTTMP = 0x04  # type bit for non-backed-up file
QTSYMLINK = 0x02  # type bit for symbolic link
QTFILE = 0x00  # type bits for plain file

# Dir.mode
DMDIR = 0x80000000  # mode bit for directories
DMAPPEND = 0x40000000  # mode bit for append only files
DMEXCL = 0x20000000  # mode bit for exclusive use files
DMMOUNT = 0x10000000  # mode bit for mounted channel
DMAUTH = 0x08000000  # mode bit for authentication file
DMTMP = 0x04000000  # mode bit for non-backed-up file
DMSYMLINK = 0x02000000  # mode bit for symbolic link (Unix, 9P2000.u)
DMDEVICE = 0x00800000  # mode bit for device file (Unix, 9P2000.u)
DMNAMEDPIPE = 0x00200000  # mode bit for named pipe (Unix, 9P2000.u)
DMSOCKET = 0x00100000  # mode bit for socket (Unix, 9P2000.u)
DMSETUID = 0x00080000  # mode bit for setuid (Unix, 9P2000.u)
DMSETGID = 0x00040000  # mode bit for setgid (Unix, 9P2000.u)

DMREAD = 0x4  # mode bit for read permission
DMWRITE = 0x2  # mode bit for write permission
DMEXEC = 0x1  # mode bit for execute permission

ERRUNDEF = 0xFFFFFFFF
UIDUNDEF = 0xFFFFFFFF

# supported authentication protocols
auths = ['pki', 'sk1']


class Error(Exception):
    pass


class EofError(Error):
    pass


class EdupfidError(Error):
    pass


class RpcError(Error):
    pass


class ServerError(Error):
    pass


class ClientError(Error):
    pass


def modetostr(mode):
    bits = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]

    def b(s):
        return bits[(mode >> s) & 7]

    d = "-"
    if mode & DMDIR:
        d = "d"
    elif mode & DMAPPEND:
        d = "a"
    return "%s%s%s%s" % (d, b(6), b(3), b(0))


def hash8(obj):
    return int(abs(hash(obj)))


def otoa(p):
    """Convert from open() to access()-style args"""
    ret = 0

    np = p & 3
    if np == OREAD:
        ret = AREAD
    elif np == OWRITE:
        ret = AWRITE
    elif np == ORDWR:
        ret = AREAD | AWRITE
    elif np == OEXEC:
        ret = AEXEC

    if p & OTRUNC:
        ret |= AWRITE

    return ret


class Marshal9P(object):
    MAXSIZE = 1024 * 1024
    chatty = False

    def __init__(self, dotu=0, chatty=False):
        self.chatty = chatty
        self.dotu = dotu

    def _splitFmt(self, fmt):
        """Split up a format string."""
        idx = 0
        r = []
        while idx < len(fmt):
            if fmt[idx] == '[':
                idx2 = fmt.find("]", idx)
                name = fmt[idx + 1:idx2]
                idx = idx2
            else:
                name = fmt[idx]
            r.append(name)
            idx += 1
        return r

    def _prep(self, fmttab):
        """Precompute encode and decode function tables."""
        encFunc, decFunc = {}, {}
        for n in dir(self):
            if n[:4] == "enc":
                encFunc[n[4:]] = self.__getattribute__(n)
            if n[:4] == "dec":
                decFunc[n[4:]] = self.__getattribute__(n)

        self.msgEncodes, self.msgDecodes = {}, {}
        for k, v in fmttab.items():
            fmts = self._splitFmt(v)
            self.msgEncodes[k] = [encFunc[fmt] for fmt in fmts]
            self.msgDecodes[k] = [decFunc[fmt] for fmt in fmts]

    def setBuf(self, bufstr=""):
        self.bytes = list(bufstr)

    def getBuf(self):
        return "".join(self.bytes)

    def _checkSize(self, v, mask):
        if v != v & mask:
            raise Error("Invalid value %d" % v)

    def _checkLen(self, x, l):
        if len(x) != l:
            raise Error("Wrong length %d, expected %d: %r" % (len(x), l, x))

    def encX(self, x):
        """Encode opaque data"""
        self.bytes += list(x)

    def decX(self, l):
        if len(self.bytes) < l:
            raise Error("buffer exhausted")
        x = "".join(self.bytes[:l])
        # del self.bytes[:l]
        # self.bytes[:l] = []  # significant speedup
        self.bytes = self.bytes[l:]  # even faster

        return x

    def encC(self, x):
        """Encode a 1-byte character"""
        return self.encX(x)

    def decC(self):
        return self.decX(1)

    def enc1(self, x):
        """Encode a 1-byte integer"""
        self._checkSize(x, 0xff)
        self.encC(chr(x))

    def dec1(self):
        return long(ord(self.decC()))

    def enc2(self, x):
        """Encode a 2-byte integer"""
        self._checkSize(x, 0xffff)
        self.enc1(x & 0xff)
        self.enc1(x >> 8)

    def dec2(self):
        return self.dec1() | (self.dec1() << 8)

    def enc4(self, x):
        """Encode a 4-byte integer"""
        self._checkSize(x, 0xffffffffL)
        self.enc2(x & 0xffff)
        self.enc2(x >> 16)

    def dec4(self):
        return self.dec2() | (self.dec2() << 16)

    def enc8(self, x):
        """Encode a 4-byte integer"""
        self._checkSize(x, 0xffffffffffffffffL)
        self.enc4(x & 0xffffffffL)
        self.enc4(x >> 32)

    def dec8(self):
        return self.dec4() | (self.dec4() << 32)

    def encS(self, x):
        """Encode length/data strings with 2-byte length"""
        self.enc2(len(x))
        self.encX(x)

    def decS(self):
        return self.decX(self.dec2())

    def encD(self, d):
        """Encode length/data arrays with 4-byte length"""
        self.enc4(len(d))
        self.encX(d)

    def decD(self):
        return self.decX(self.dec4())

    def encQ(self, q):
        self.enc1(q.type)
        self.enc4(q.vers)
        self.enc8(q.path)

    def decQ(self):
        return Qid(self.dec1(), self.dec4(), self.dec8())

    def _checkType(self, t):
        if t not in cmdName:
            raise Error("Invalid message type %d" % t)

    def _checkResid(self):
        if len(self.bytes):
            raise Error("Extra information in message: %r" % self.bytes)

    def send(self, fd, fcall):
        """Format and send a message"""
        self.setBuf()
        self._checkType(fcall.type)
        if self.chatty:
            print "-%d->" % fd.fileno(), cmdName[fcall.type], fcall.tag, fcall.tostr()
        self.enc1(fcall.type)
        self.enc2(fcall.tag)
        self.enc(fcall)
        self.enc4(len(self.bytes) + 4)
        self.bytes = self.bytes[-4:] + self.bytes[:-4]
        fd.write(self.getBuf())

    def recv(self, fd):
        """Read and decode a message"""
        self.setBuf(fd.read(4))
        size = self.dec4()
        if size > self.MAXSIZE or size < 4:
            raise Error("Bad message size: %d" % size)
        self.setBuf(fd.read(size - 4))
        mtype, tag = self.dec1(), self.dec2()
        self._checkType(mtype)
        fcall = Fcall(mtype, tag)
        self.dec(fcall)
        self._checkResid()
        if self.chatty:
            print "<-%d-" % fd.fileno(), cmdName[mtype], tag, fcall.tostr()
        return fcall

    def encstat(self, fcall, enclen=1):
        statsz = 0
        if enclen:
            for x in fcall.stat:
                if self.dotu:
                    statsz = 2 + 4 + 13 + 4 + 4 + 4 + 8 + len(x.name) + len(x.uid) + len(x.gid) + len(
                        x.muid) + 2 + 2 + 2 + 2 + len(x.extension) + 2 + 4 + 4 + 4
                else:
                    statsz = 2 + 4 + 13 + 4 + 4 + 4 + 8 + len(x.name) + len(x.uid) + len(x.gid) + len(
                        x.muid) + 2 + 2 + 2 + 2
            self.enc2(statsz + 2)

        for x in fcall.stat:
            self.enc2(statsz)
            self.enc2(x.type)
            self.enc4(x.dev)
            self.encQ(x.qid)
            self.enc4(x.mode)
            self.enc4(x.atime)
            self.enc4(x.mtime)
            self.enc8(x.length)
            self.encS(x.name)
            self.encS(x.uid)
            self.encS(x.gid)
            self.encS(x.muid)
            if self.dotu:
                self.encS(x.extension)
                self.enc4(x.uidnum)
                self.enc4(x.gidnum)
                self.enc4(x.muidnum)

    def enc(self, fcall):
        if fcall.type in (Tversion, Rversion):
            self.enc4(fcall.msize)
            self.encS(fcall.version)
        elif fcall.type == Tauth:
            self.enc4(fcall.afid)
            self.encS(fcall.uname)
            self.encS(fcall.aname)
            if self.dotu:
                self.enc4(fcall.uidnum)
        elif fcall.type == Rauth:
            self.encQ(fcall.aqid)
        elif fcall.type == Rerror:
            self.encS(fcall.ename)
            if self.dotu:
                self.enc4(fcall.errno)
        elif fcall.type == Tflush:
            self.enc2(fcall.oldtag)
        elif fcall.type == Tattach:
            self.enc4(fcall.fid)
            self.enc4(fcall.afid)
            self.encS(fcall.uname)
            self.encS(fcall.aname)
            if self.dotu:
                self.enc4(fcall.uidnum)
        elif fcall.type == Rattach:
            self.encQ(fcall.qid)
        elif fcall.type == Twalk:
            self.enc4(fcall.fid)
            self.enc4(fcall.newfid)
            self.enc2(len(fcall.wname))
            for x in fcall.wname:
                self.encS(x)
        elif fcall.type == Rwalk:
            self.enc2(len(fcall.wqid))
            for x in fcall.wqid:
                self.encQ(x)
        elif fcall.type == Topen:
            self.enc4(fcall.fid)
            self.enc1(fcall.mode)
        elif fcall.type in (Ropen, Rcreate):
            self.encQ(fcall.qid)
            self.enc4(fcall.iounit)
        elif fcall.type == Tcreate:
            self.enc4(fcall.fid)
            self.encS(fcall.name)
            self.enc4(fcall.perm)
            self.enc1(fcall.mode)
            if self.dotu:
                self.encS(fcall.extension)
        elif fcall.type == Tread:
            self.enc4(fcall.fid)
            self.enc8(fcall.offset)
            self.enc4(fcall.count)
        elif fcall.type == Rread:
            self.encD(fcall.data)
        elif fcall.type == Twrite:
            self.enc4(fcall.fid)
            self.enc8(fcall.offset)
            self.enc4(len(fcall.data))
            self.encX(fcall.data)
        elif fcall.type == Rwrite:
            self.enc4(fcall.count)
        elif fcall.type in (Tclunk, Tremove, Tstat):
            self.enc4(fcall.fid)
        elif fcall.type in (Rstat, Twstat):
            if fcall.type == Twstat:
                self.enc4(fcall.fid)
            self.encstat(fcall, 1)

    def decstat(self, fcall, enclen=0):
        fcall.stat = []
        if enclen:
            totsz = self.dec2()
        while len(self.bytes):
            size = self.dec2()
            b = self.bytes
            self.bytes = b[0:size]

            stat = Dir(self.dotu)
            stat.type = self.dec2()  # type
            stat.dev = self.dec4()  # dev
            stat.qid = self.decQ()  # qid
            stat.mode = self.dec4()  # mode
            stat.atime = self.dec4()  # atime
            stat.mtime = self.dec4()  # mtime
            stat.length = self.dec8()  # length
            stat.name = self.decS()  # name
            stat.uid = self.decS()  # uid
            stat.gid = self.decS()  # gid
            stat.muid = self.decS()  # muid
            if self.dotu:
                stat.extension = self.decS()
                stat.uidnum = self.dec4()
                stat.gidnum = self.dec4()
                stat.muidnum = self.dec4()
            fcall.stat.append(stat)
            self.bytes = b[size:]
            # self.bytes[0:size] = []

    def dec(self, fcall):
        if fcall.type in (Tversion, Rversion):
            fcall.msize = self.dec4()
            fcall.version = self.decS()
        elif fcall.type == Tauth:
            fcall.afid = self.dec4()
            fcall.uname = self.decS()
            fcall.aname = self.decS()
            if self.dotu:
                fcall.uidnum = self.dec4()
        elif fcall.type == Rauth:
            fcall.aqid = self.decQ()
        elif fcall.type == Rerror:
            fcall.ename = self.decS()
            if self.dotu:
                fcall.errno = self.dec4()
        elif fcall.type == Tflush:
            fcall.oldtag = self.dec2()
        elif fcall.type == Tattach:
            fcall.fid = self.dec4()
            fcall.afid = self.dec4()
            fcall.uname = self.decS()
            fcall.aname = self.decS()
            if self.dotu:
                fcall.uidnum = self.dec4()
        elif fcall.type == Rattach:
            fcall.qid = self.decQ()
        elif fcall.type == Twalk:
            fcall.fid = self.dec4()
            fcall.newfid = self.dec4()
            fcall.nwname = self.dec2()
            fcall.wname = [self.decS() for _ in xrange(fcall.nwname)]
        elif fcall.type == Rwalk:
            fcall.nwqid = self.dec2()
            fcall.wqid = [self.decQ() for _ in xrange(fcall.nwqid)]
        elif fcall.type == Topen:
            fcall.fid = self.dec4()
            fcall.mode = self.dec1()
        elif fcall.type in (Ropen, Rcreate):
            fcall.qid = self.decQ()
            fcall.iounit = self.dec4()
        elif fcall.type == Tcreate:
            fcall.fid = self.dec4()
            fcall.name = self.decS()
            fcall.perm = self.dec4()
            fcall.mode = self.dec1()
            if self.dotu:
                fcall.extension = self.decS()
        elif fcall.type == Tread:
            fcall.fid = self.dec4()
            fcall.offset = self.dec8()
            fcall.count = self.dec4()
        elif fcall.type == Rread:
            fcall.data = self.decD()
        elif fcall.type == Twrite:
            fcall.fid = self.dec4()
            fcall.offset = self.dec8()
            fcall.count = self.dec4()
            fcall.data = self.decX(fcall.count)
        elif fcall.type == Rwrite:
            fcall.count = self.dec4()
        elif fcall.type in (Tclunk, Tremove, Tstat):
            fcall.fid = self.dec4()
        elif fcall.type in (Rstat, Twstat):
            if fcall.type == Twstat:
                fcall.fid = self.dec4()
            self.decstat(fcall, 1)

        return fcall


class Fcall(object):
    """
    possible values, from p9p's fcall.h
    msize       # Tversion, Rversion
    version     # Tversion, Rversion
    oldtag      # Tflush
    ename       # Rerror
    qid         # Rattach, Ropen, Rcreate
    iounit      # Ropen, Rcreate
    aqid        # Rauth
    afid        # Tauth, Tattach
    uname       # Tauth, Tattach
    aname       # Tauth, Tattach
    perm        # Tcreate
    name        # Tcreate
    mode        # Tcreate, Topen
    newfid      # Twalk
    nwname      # Twalk
    wname       # Twalk, array
    nwqid       # Rwalk
    wqid        # Rwalk, array
    offset      # Tread, Twrite
    count       # Tread, Twrite, Rread
    data        # Twrite, Rread
    nstat       # Twstat, Rstat
    stat        # Twstat, Rstat

    # dotu extensions:
    errno       # Rerror
    extension   # Tcreate
    """

    def __init__(self, fctype, tag=1, fid=None):
        self.type = fctype
        self.fid = fid
        self.tag = tag

    def tostr(self):
        attr = [x for x in dir(self) if not x.startswith('_') and not x.startswith('tostr')]

        ret = ' '.join("%s=%s" % (x, getattr(self, x)) for x in attr)
        ret = "%s %s" % (cmdName[self.type], ret)

        return repr(ret)


class Qid(object):
    def __init__(self, qtype=None, vers=None, path=None):
        self.type = qtype
        self.vers = vers
        self.path = path

    def __str__(self):
        return '(%x,%x,%x)' % (self.type, self.vers, self.path)

    __repr__ = __str__


class Fid(object):
    def __init__(self, pool, fid, path='', auth=0):
        if fid in pool:
            raise EdupfidError(Edupfid)
        self.fid = fid
        self.ref = 1
        self.omode = -1
        self.auth = auth
        self.uid = None
        self.qid = None
        self.path = path

        pool[fid] = self


class Dir(object):
    """
    A directory object.
    """

    def __init__(self, dotu=0, *args):
        """
        :param dotu:
        :type dotu:  int
        :param type: server type
        :param dev:  server subtype

        file data:

        :param qid:    unique id from server
        :type qid:     Qid
        :param mode:   permissions
        :type mode:    long
        :param atime:  last read time
        :type atime:   long
        :param mtime:  last write time
        :type mtime:   long
        :param length: file length
        :type length:  long
        :param name:   file name
        :type name:    str

        :param uid:    owner name
        :type uid:     str
        :param gid:    group name
        :type gid:     str
        :param muid:   last modifier name
        :type muid:    str

        9P2000.u extensions::

        :param uidnum        numeric uid
        :param gidnum        numeric gid
        :param muidnum       numeric muid
        :param *ext          extended info
        """
        self.dotu = dotu
        # the dotu arguments will be added separately. this is not
        # straightforward but is cleaner.
        if len(args):
            (self.type,
             self.dev,
             self.qid,
             self.mode,
             self.atime,
             self.mtime,
             self.length,
             self.name,
             self.uid,
             self.gid,
             self.muid) = args[:11]

            if dotu:
                (self.extension,
                 self.uidnum,
                 self.gidnum,
                 self.muidnum) = args[11:15]
            else:
                (self.extension,
                 self.uidnum,
                 self.gidnum,
                 self.muidnum) = "", UIDUNDEF, UIDUNDEF, UIDUNDEF

    def tolstr(self, dirname=""):
        if dirname != '':
            dirname += '/'
        dirname += self.name
        if self.dotu:
            return "%s %d %d %-8d\t\t%s" % (modetostr(self.mode), self.uidnum, self.gidnum, self.length, dirname)
        else:
            return "%s %s %s %-8d\t\t%s" % (modetostr(self.mode), self.uid, self.gid, self.length, dirname)

    def todata(self, marsh):
        """
        This circumvents a leftover from the original 9P python implementation.
        Why do enc functions have to hide data in "bytes"? I don't know
        """

        marsh.setBuf()
        if marsh.dotu:
            size = 2 + 4 + 13 + 4 + 4 + 4 + 8 + len(self.name) + len(self.uid) + len(self.gid) + len(
                self.muid) + 2 + 2 + 2 + 2 + len(self.extension) + 2 + 4 + 4 + 4
        else:
            size = 2 + 4 + 13 + 4 + 4 + 4 + 8 + len(self.name) + len(self.uid) + len(self.gid) + len(
                self.muid) + 2 + 2 + 2 + 2
        marsh.enc2(size)
        marsh.enc2(self.type)
        marsh.enc4(self.dev)
        marsh.encQ(self.qid)
        marsh.enc4(self.mode)
        marsh.enc4(self.atime)
        marsh.enc4(self.mtime)
        marsh.enc8(self.length)
        marsh.encS(self.name)
        marsh.encS(self.uid)
        marsh.encS(self.gid)
        marsh.encS(self.muid)
        if marsh.dotu:
            marsh.encS(self.extension)
            marsh.enc4(self.uidnum)
            marsh.enc4(self.gidnum)
            marsh.enc4(self.muidnum)
        return marsh.bytes


class Req(object):
    def __init__(self, tag, fd=None, ifcall=None, ofcall=None, dir=None, oldreq=None,
                 fid=None, afid=None, newfid=None):
        self.tag = tag
        self.fd = fd
        self.ifcall = ifcall
        self.ofcall = ofcall
        self.dir = dir
        self.oldreq = oldreq
        self.fid = fid
        self.afid = afid
        self.newfid = newfid


class Client(object):
    """
    An authless client interface to the protocol.
    """
    AFID = 10
    ROOT = 11
    CWD = 12
    F = 13

    path = ''  # for 'getwd' equivalent
    chatty = 0
    msize = 8192

    def __init__(self, fd, user=None, chatty=0, msize=8192):
        fd.dotu = 0
        fd.chatty = chatty
        self.fd = fd
        self.chatty = chatty
        self.msize = msize
        self.login(user)

    def _rpc(self, fcall):
        if fcall.type == Tversion:
            fcall.tag = NOTAG
        self.fd.send(fcall)
        try:
            ifcall = self.fd.recv()
        except (KeyboardInterrupt, Exception) as e:
            # try to flush the operation, then rethrow exception
            if fcall.type != Tflush:
                self._flush(fcall.tag, fcall.tag + 1)
            raise e
        if ifcall.tag != fcall.tag:
            raise RpcError("invalid tag received")
        if ifcall.type == Rerror:
            raise RpcError(ifcall.ename)
        if ifcall.type != fcall.type + 1:
            raise ClientError("incorrect reply from server: %r" % [fcall.type, fcall.tag])
        return ifcall

    # protocol calls; part of 9p
    # should be private functions, really
    def _version(self, msize, version):
        fcall = Fcall(Tversion)
        self.msize = msize
        fcall.msize = msize
        fcall.version = version
        return self._rpc(fcall)

    def _auth(self, afid, uname, aname):
        fcall = Fcall(Tauth)
        fcall.afid = afid
        fcall.uname = uname
        fcall.aname = aname
        return self._rpc(fcall)

    def _attach(self, fid, afid, uname, aname):
        fcall = Fcall(Tattach)
        fcall.fid = fid
        fcall.afid = afid
        fcall.uname = uname
        fcall.aname = aname
        return self._rpc(fcall)

    def _walk(self, fid, newfid, wnames):
        fcall = Fcall(Twalk)
        fcall.fid = fid
        fcall.newfid = newfid
        fcall.wname = wnames
        return self._rpc(fcall)

    def _open(self, fid, mode):
        fcall = Fcall(Topen)
        fcall.fid = fid
        fcall.mode = mode
        return self._rpc(fcall)

    def _create(self, fid, name, perm, mode):
        fcall = Fcall(Tcreate)
        fcall.fid = fid
        fcall.name = name
        fcall.perm = perm
        fcall.mode = mode
        return self._rpc(fcall)

    def _read(self, fid, off, count):
        fcall = Fcall(Tread)
        fcall.fid = fid
        fcall.offset = off
        if count > self.msize - IOHDRSZ:
            count = self.msize - IOHDRSZ
        fcall.count = count
        return self._rpc(fcall)

    def _write(self, fid, off, data):
        fcall = Fcall(Twrite)
        fcall.fid = fid
        fcall.offset = off
        fcall.data = data
        return self._rpc(fcall)

    def _clunk(self, fid):
        fcall = Fcall(Tclunk)
        fcall.fid = fid
        return self._rpc(fcall)

    def _remove(self, fid):
        fcall = Fcall(Tremove)
        fcall.fid = fid
        return self._rpc(fcall)

    def _stat(self, fid):
        fcall = Fcall(Tstat)
        fcall.fid = fid
        return self._rpc(fcall)

    def _wstat(self, fid, stats):
        fcall = Fcall(Twstat)
        fcall.fid = fid
        fcall.stats = stats
        return self._rpc(fcall)

    def _flush(self, tag, oldtag):
        fcall = Fcall(Tflush, tag=tag)
        fcall.oldtag = tag
        return self._rpc(fcall)

    def _fullclose(self):
        self._clunk(self.ROOT)
        self._clunk(self.CWD)
        self.fd.close()

    def login(self, user):
        fcall = self._version(self.msize, version)
        if fcall.version != version:
            raise ClientError("version mismatch: %r" % fcall.version)

        fcall.afid = NOFID

        self._attach(self.ROOT, fcall.afid, user, "")

        self._walk(self.ROOT, self.CWD, [])
        self.path = '/'

    # user accessible calls, the actual implementation of a client
    def close(self):
        self._clunk(self.F)

    def walk(self, pstr=''):
        root = self.CWD
        if pstr == '':
            path = []
        elif pstr.find('/') == -1:
            path = [pstr]
        else:
            path = pstr.split("/")
            if path[0] == '':
                root = self.ROOT
                path = path[1:]
            path = filter(None, path)

        fcall = self._walk(root, self.F, path)
        if len(fcall.wqid) < len(path):
            raise RpcError('incomplete walk (%d out of %d)' % (len(fcall.wqid), len(path)))
        return fcall.wqid

    def open(self, pstr='', mode=0):
        if self.walk(pstr) is None:
            return
        self.pos = 0L
        try:
            fcall = self._open(self.F, mode)
        except RpcError as e:
            print "%s: %s" % (pstr, e.args[0])
            self.close()
            raise
        return fcall

    def create(self, pstr, perm=0644, mode=1):
        p = pstr.split("/")
        pstr2, name = "/".join(p[:-1]), p[-1]
        if self.walk(pstr2) is None:
            return
        self.pos = 0L
        try:
            return self._create(self.F, name, perm, mode)
        except RpcError:
            self.close()
            raise

    def rm(self, pstr):
        self.open(pstr)
        try:
            self._remove(self.F)
        except RpcError:
            raise

    def read(self, l):
        try:
            fcall = self._read(self.F, self.pos, l)
            buf = fcall.data
        except RpcError:
            self.close()
            raise

        self.pos += len(buf)
        return buf

    def write(self, buf):
        try:
            l = self._write(self.F, self.pos, buf).count
            self.pos += l
            return l
        except RpcError:
            self.close()
            raise

    def stat(self, pstr):
        if self.walk(pstr) is None:
            return
        try:
            fc = self._stat(self.F)
        finally:
            self.close()
        return fc.stat

    def lsdir(self):
        ret = []
        while 1:
            buf = self.read(self.msize)
            if len(buf) == 0:
                break
            p9 = Marshal9P()
            p9.setBuf(buf)
            fcall = Fcall(Rstat)
            try:
                p9.decstat(fcall, 0)
            except:
                self.close()
                print >> sys.stderr, 'unexpected decstat error:', traceback.print_exc()
                raise
            ret.extend(fcall.stat)
        return ret

    def ls(self, longnames=False, args=None):
        ret = []

        if not args:
            if self.open() is None:
                return
            if longnames:
                ret = [z.tolstr() for z in self.lsdir()]
            else:
                ret = [z.name for z in self.lsdir()]
            self.close()
        else:
            for x in args:
                stat = self.stat(x)
                if not stat:
                    return  # stat already printed a message
                if len(stat) == 1:
                    if stat[0].mode & DMDIR:
                        self.open(x)
                        lsd = self.lsdir()
                        if longnames:
                            ret += [z.tolstr() for z in lsd]
                        else:
                            ret += [x + '/' + z.name for z in lsd]
                        self.close()
                    else:
                        if longnames:
                            # we already have full path+name, but tolstr() wants
                            # to append the name to the end anyway, so strip
                            # the last basename out to form identical path+name
                            ret.append(stat[0].tolstr(x[0:-len(stat[0].name) - 1]))
                        else:
                            ret.append(x)
                else:
                    print '%s: returned multiple stats (internal error)' % x
        return ret

    def cd(self, pstr):
        q = self.walk(pstr)
        if q is None:
            return 0
        if q and not (q[-1].type & QTDIR):
            print "%s: not a directory" % pstr
            self.close()
            return 0
        self.F, self.CWD = self.CWD, self.F
        self.close()
        return 1


