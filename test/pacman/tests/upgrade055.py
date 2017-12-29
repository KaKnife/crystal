self.description = "Upgrade a package that provides one of two imaginary packages"

lp1 = pmpkg("pkg1")
lp1.depends = ["imaginary", "imaginary2"]
self.addpkg2db("local", lp1)

lp2 = pmpkg("pkg2")
lp2.provides = ["imaginary"]
self.addpkg2db("local", lp2)

lp3 = pmpkg("pkg3")
lp3.provides = ["imaginary2"]
self.addpkg2db("local", lp3)

p = pmpkg("pkg2", "1.0-2")
p.provides = ["imaginary"]
self.addpkg(p)

self.args = "-U %s" % p.filename()

self.addrule("PACMAN_RETCODE=0")
self.addrule("PKG_EXIST=pkg1")
self.addrule("PKG_VERSION=pkg2|1.0-2")
self.addrule("PKG_EXIST=pkg3")
self.addrule("PKG_DEPENDS=pkg1|imaginary")
