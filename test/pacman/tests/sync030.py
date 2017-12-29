self.description = "Sync packages non-explicitly"

lp1 = pmpkg("pkg1")
lp1.reason = 0
self.addpkg2db("local", lp1)

p1 = pmpkg("pkg1", "1.0-2")
p2 = pmpkg("pkg2", "1.0-2")

for p in p1, p2:
	self.addpkg2db("sync", p)

self.args = "-S --asdeps %s" % " ".join([p.name for p in (p1, p2)])

self.addrule("PACMAN_RETCODE=0")
self.addrule("PKG_VERSION=pkg1|1.0-2")
self.addrule("PKG_VERSION=pkg2|1.0-2")
self.addrule("PKG_REASON=pkg1|1")
self.addrule("PKG_REASON=pkg2|1")
