self.description = "Fileconflict with symlinks"

lp = pmpkg("dummy")
lp.files = ["dir/realdir/",
            "dir/realdir/realfile",
            "dir/symdir -> realdir"]
self.addpkg2db("local", lp)

p1 = pmpkg("pkg1")
p1.files = ["dir/",
            "dir/realdir/",
            "dir/realdir/file"]
self.addpkg(p1)

p2 = pmpkg("pkg2")
p2.files = ["dir/",
            "dir/symdir/",
            "dir/symdir/file"]
self.addpkg(p2)

self.args = "-U %s" % " ".join([p.filename() for p in (p1, p2)])

self.addrule("PACMAN_RETCODE=1")
self.addrule("!PKG_EXIST=pkg1")
self.addrule("!PKG_EXIST=pkg2")
self.addrule("FILE_EXIST=dir/realdir/realfile")
self.addrule("!FILE_EXIST=dir/realdir/file")
