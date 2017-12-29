self.description = "pkg2<2.0 dependency (not satisfy)"

p = pmpkg("pkg1")
p.depends = ["pkg2<2.0"]
self.addpkg(p)

lp = pmpkg("pkg2", "2.0-3")
self.addpkg2db("local", lp)

self.args = "-U %s" % p.filename()

self.addrule("PACMAN_RETCODE=1")
self.addrule("!PKG_EXIST=pkg1")
self.addrule("PKG_EXIST=pkg2")
