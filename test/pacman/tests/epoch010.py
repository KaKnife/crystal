self.description = "usbutils case study: force in new package"

sp = pmpkg("usbutils", "1:001-1")
self.addpkg2db("sync", sp)

lp = pmpkg("usbutils", "0.91-4")
self.addpkg2db("local", lp)

self.args = "-Su"

self.addrule("PACMAN_RETCODE=0")
self.addrule("PKG_VERSION=usbutils|1:001-1")
