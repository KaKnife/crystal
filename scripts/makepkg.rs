// #   makepkg - make packages compatible for use with pacman
// #   @configure_input@
// #
// #   Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>
// #   Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
// #   Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
// #   Copyright (c) 2006 by Miklos Vajna <vmiklos@frugalware.org>
// #   Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
// #   Copyright (c) 2006 by Alex Smith <alex@alex-smith.me.uk>
// #   Copyright (c) 2006 by Andras Voroskoi <voroskoi@frugalware.org>
// #
// #   This program is free software; you can redistribute it and/or modify
// #   it under the terms of the GNU General Public License as published by
// #   the Free Software Foundation; either version 2 of the License, or
// #   (at your option) any later version.
// #
// #   This program is distributed in the hope that it will be useful,
// #   but WITHOUT ANY WARRANTY; without even the implied warranty of
// #   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// #   GNU General Public License for more details.
// #
// #   You should have received a copy of the GNU General Public License
// #   along with this program.  If not, see <http://www.gnu.org/licenses/>.
// #

// # makepkg uses quite a few external programs during its execution. You
// # need to have at least the following installed for makepkg to function:
// #   awk, bsdtar (libarchive), bzip2, coreutils, fakeroot, file, find (findutils),
// #   gettext, gpg, grep, gzip, sed, tput (ncurses), xz

// # gettext initialization
// export TEXTDOMAIN='pacman-scripts'
// export TEXTDOMAINDIR='@localedir@'

// # file -i does not work on Mac OSX unless legacy mode is set
// export COMMAND_MODE='legacy'
// # Ensure CDPATH doesn't screw with our cd calls
// unset CDPATH
// # Ensure GREP_OPTIONS doesn't screw with our grep calls
// unset GREP_OPTIONS

// declare -r makepkg_version='@PACKAGE_VERSION@'
// declare -r confdir='@sysconfdir@'
// declare -r BUILDSCRIPT='@BUILDSCRIPT@'
// declare -r startdir="$PWD"

// LIBRARY=${LIBRARY:-'@libmakepkgdir@'}

// build_options=('ccache' 'distcc' 'buildflags' 'makeflags')
// splitpkg_overrides=('pkgdesc' 'arch' 'url' 'license' 'groups' 'depends'
//                     'optdepends' 'provides' 'conflicts' 'replaces' 'backup'
//                     'options' 'install' 'changelog')
// readonly -a build_options splitpkg_overrides

// known_hash_algos=('md5' 'sha1' 'sha224' 'sha256' 'sha384' 'sha512' 'whirlpool')

// # Options
// ASDEPS=0
// BUILDFUNC=0
// CHECKFUNC=0
// CLEANBUILD=0
// CLEANUP=0
// DEP_BIN=0
// FORCE=0
// GENINTEG=0
// HOLDVER=0
// IGNOREARCH=0
// INFAKEROOT=0
// INSTALL=0
// LOGGING=0
// NEEDED=0
// NOARCHIVE=0
// NOBUILD=0
// NODEPS=0
// NOEXTRACT=0
// PKGFUNC=0
// PKGVERFUNC=0
// PREPAREFUNC=0
// REPKG=0
// REPRODUCIBLE=0
// RMDEPS=0
// SKIPCHECKSUMS=0
// SKIPPGPCHECK=0
// SIGNPKG=''
// SPLITPKG=0
// SOURCEONLY=0
// VERIFYSOURCE=0

// if [[ -n $SOURCE_DATE_EPOCH ]]; then
// 	REPRODUCIBLE=1
// else
// 	SOURCE_DATE_EPOCH=$(date +%s)
// fi
// export SOURCE_DATE_EPOCH

// PACMAN_OPTS=()

// shopt -s extglob

// ### SUBROUTINES ###

// # Import libmakepkg
// for lib in "$LIBRARY"/*.sh; do
// 	source "$lib"
// done

// ##
// # Special exit call for traps, Don't print any error messages when inside,
// # the fakeroot call, the error message will be printed by the main call.
// ##
// trap_exit() {
// 	local signal=$1; shift

// 	if (( ! INFAKEROOT )); then
// 		echo
// 		error "$@"
// 	fi
// 	[[ -n $srclinks ]] && rm -rf "$srclinks"

// 	# unset the trap for this signal, and then call the default handler
// 	trap -- "$signal"
// 	kill "-$signal" "$$"
// }


// ##
// # Clean up function. Called automatically when the script exits.
// ##
// clean_up() {
// 	local EXIT_CODE=$?

// 	if (( INFAKEROOT )); then
// 		# Don't clean up when leaving fakeroot, we're not done yet.
// 		return
// 	fi

// 	if (( ! EXIT_CODE && CLEANUP )); then
// 		local pkg file

// 		# If it's a clean exit and -c/--clean has been passed...
// 		msg "$(gettext "Cleaning up...")"
// 		rm -rf "$pkgdirbase" "$srcdir"
// 		if [[ -n $pkgbase ]]; then
// 			local fullver=$(get_full_version)
// 			# Can't do this unless the BUILDSCRIPT has been sourced.
// 			if (( PKGVERFUNC )); then
// 				rm -f "${pkgbase}-${fullver}-${CARCH}-pkgver.log"*
// 			fi
// 			if (( PREPAREFUNC )); then
// 				rm -f "${pkgbase}-${fullver}-${CARCH}-prepare.log"*
// 			fi
// 			if (( BUILDFUNC )); then
// 				rm -f "${pkgbase}-${fullver}-${CARCH}-build.log"*
// 			fi
// 			if (( CHECKFUNC )); then
// 				rm -f "${pkgbase}-${fullver}-${CARCH}-check.log"*
// 			fi
// 			if (( PKGFUNC )); then
// 				rm -f "${pkgbase}-${fullver}-${CARCH}-package.log"*
// 			elif (( SPLITPKG )); then
// 				for pkg in ${pkgname[@]}; do
// 					rm -f "${pkgbase}-${fullver}-${CARCH}-package_${pkg}.log"*
// 				done
// 			fi

// 			# clean up dangling symlinks to packages
// 			for pkg in ${pkgname[@]}; do
// 				for file in ${pkg}-*-*-*{${PKGEXT},${SRCEXT}}; do
// 					if [[ -h $file && ! -e $file ]]; then
// 						rm -f "$file"
// 					fi
// 				done
// 			done
// 		fi
// 	fi

// 	remove_deps
// }

// enter_fakeroot() {
// 	msg "$(gettext "Entering %s environment...")" "fakeroot"
// 	fakeroot -- $0 -F "${ARGLIST[@]}" || exit $?
// }

// # Automatically update pkgver variable if a pkgver() function is provided
// # Re-sources the PKGBUILD afterwards to allow for other variables that use $pkgver
// update_pkgver() {
// 	newpkgver=$(run_function_safe pkgver)
// 	if ! check_pkgver "$newpkgver"; then
// 		error "$(gettext "pkgver() generated an invalid version: %s")" "$newpkgver"
// 		exit 1
// 	fi

// 	if [[ -n $newpkgver && $newpkgver != "$pkgver" ]]; then
// 		if [[ -f $BUILDFILE && -w $BUILDFILE ]]; then
// 			if ! @SEDPATH@ @SEDINPLACEFLAGS@ "s:^pkgver=[^ ]*:pkgver=$newpkgver:" "$BUILDFILE"; then
// 				error "$(gettext "Failed to update %s from %s to %s")" \
// 						"pkgver" "$pkgver" "$newpkgver"
// 				exit 1
// 			fi
// 			@SEDPATH@ @SEDINPLACEFLAGS@ "s:^pkgrel=[^ ]*:pkgrel=1:" "$BUILDFILE"
// 			source_safe "$BUILDFILE"
// 			local fullver=$(get_full_version)
// 			msg "$(gettext "Updated version: %s")" "$pkgbase $fullver"
// 		else
// 			warning "$(gettext "%s is not writeable -- pkgver will not be updated")" \
// 					"$BUILDFILE"
// 		fi
// 	fi
// }

// # Print 'source not found' error message and exit makepkg
// missing_source_file() {
// 	error "$(gettext "Unable to find source file %s.")" "$(get_filename "$1")"
// 	plain "$(gettext "Aborting...")"
// 	exit 1 # $E_MISSING_FILE
// }

// run_pacman() {
// 	local cmd
// 	if [[ $1 != -@(T|Qq) ]]; then
// 		cmd=("$PACMAN_PATH" "${PACMAN_OPTS[@]}" "$@")
// 	else
// 		cmd=("$PACMAN_PATH" "$@")
// 	fi
// 	if [[ $1 != -@(T|Qq|Q) ]]; then
// 		if type -p sudo >/dev/null; then
// 			cmd=(sudo "${cmd[@]}")
// 		else
// 			cmd=(su root -c "$(printf '%q ' "${cmd[@]}")")
// 		fi
// 	fi
// 	"${cmd[@]}"
// }

// check_deps() {
// 	(( $# > 0 )) || return 0

// 	local ret=0
// 	local pmout
// 	pmout=$(run_pacman -T "$@")
// 	ret=$?

// 	if (( ret == 127 )); then #unresolved deps
// 		printf "%s\n" "$pmout"
// 	elif (( ret )); then
// 		error "$(gettext "'%s' returned a fatal error (%i): %s")" "$PACMAN" "$ret" "$pmout"
// 		return "$ret"
// 	fi
// }

// handle_deps() {
// 	local R_DEPS_SATISFIED=0
// 	local R_DEPS_MISSING=1

// 	(( $# == 0 )) && return $R_DEPS_SATISFIED

// 	local deplist=("$@")

// 	if (( ! DEP_BIN )); then
// 		return $R_DEPS_MISSING
// 	fi

// 	if (( DEP_BIN )); then
// 		# install missing deps from binary packages (using pacman -S)
// 		msg "$(gettext "Installing missing dependencies...")"

// 		if ! run_pacman -S --asdeps "${deplist[@]}"; then
// 			error "$(gettext "'%s' failed to install missing dependencies.")" "$PACMAN"
// 			exit 1 # TODO: error code
// 		fi
// 	fi

// 	# we might need the new system environment
// 	# save our shell options and turn off extglob
// 	local shellopts=$(shopt -p)
// 	shopt -u extglob
// 	source /etc/profile &>/dev/null
// 	eval "$shellopts"

// 	return $R_DEPS_SATISFIED
// }

// resolve_deps() {
// 	local R_DEPS_SATISFIED=0
// 	local R_DEPS_MISSING=1

// 	# deplist cannot be declared like this: local deplist=$(foo)
// 	# Otherwise, the return value will depend on the assignment.
// 	local deplist
// 	deplist=($(check_deps "$@")) || exit 1
// 	[[ -z $deplist ]] && return $R_DEPS_SATISFIED

// 	if handle_deps "${deplist[@]}"; then
// 		# check deps again to make sure they were resolved
// 		deplist=$(check_deps "$@") || exit 1
// 		[[ -z $deplist ]] && return $R_DEPS_SATISFIED
// 	fi

// 	msg "$(gettext "Missing dependencies:")"
// 	local dep
// 	for dep in $deplist; do
// 		msg2 "$dep"
// 	done

// 	return $R_DEPS_MISSING
// }

// remove_deps() {
// 	(( ! RMDEPS )) && return

// 	# check for packages removed during dependency install (e.g. due to conflicts)
// 	# removing all installed packages is risky in this case
// 	if [[ -n $(grep -xvFf <(printf '%s\n' "${current_pkglist[@]}") \
// 			<(printf '%s\n' "${original_pkglist[@]}")) ]]; then
// 		warning "$(gettext "Failed to remove installed dependencies.")"
// 		return 0
// 	fi

// 	local deplist
// 	deplist=($(grep -xvFf <(printf "%s\n" "${original_pkglist[@]}") \
// 			<(printf "%s\n" "${current_pkglist[@]}")))
// 	if [[ -z $deplist ]]; then
// 		return 0
// 	fi

// 	msg "Removing installed dependencies..."
// 	# exit cleanly on failure to remove deps as package has been built successfully
// 	if ! run_pacman -Rn ${deplist[@]}; then
// 		warning "$(gettext "Failed to remove installed dependencies.")"
// 		return 0
// 	fi
// }

// error_function() {
// 	if [[ -p $logpipe ]]; then
// 		rm "$logpipe"
// 	fi
// 	# first exit all subshells, then print the error
// 	if (( ! BASH_SUBSHELL )); then
// 		error "$(gettext "A failure occurred in %s().")" "$1"
// 		plain "$(gettext "Aborting...")"
// 	fi
// 	exit 2 # $E_BUILD_FAILED
// }

// source_safe() {
// 	shopt -u extglob
// 	if ! source "$@"; then
// 		error "$(gettext "Failed to source %s")" "$1"
// 		exit 1
// 	fi
// 	shopt -s extglob
// }

// merge_arch_attrs() {
// 	local attr supported_attrs=(
// 		provides conflicts depends replaces optdepends
// 		makedepends checkdepends)

// 	for attr in "${supported_attrs[@]}"; do
// 		eval "$attr+=(\"\${${attr}_$CARCH[@]}\")"
// 	done

// 	# ensure that calling this function is idempotent.
// 	unset -v "${supported_attrs[@]/%/_$CARCH}"
// }

// source_buildfile() {
// 	source_safe "$@"
// }

// prepare_buildenv() {
// 	# clear user-specified buildflags if requested
// 	if check_option "buildflags" "n"; then
// 		unset CPPFLAGS CFLAGS CXXFLAGS LDFLAGS
// 	fi

// 	if check_option "debug" "y"; then
// 		CFLAGS+=" $DEBUG_CFLAGS"
// 		CXXFLAGS+=" $DEBUG_CXXFLAGS"
// 	fi

// 	# clear user-specified makeflags if requested
// 	if check_option "makeflags" "n"; then
// 		unset MAKEFLAGS
// 	fi

// 	# ensure all necessary build variables are exported
// 	export CPPFLAGS CFLAGS CXXFLAGS LDFLAGS MAKEFLAGS CHOST

// 	local ccache=0

// 	# use ccache if it is requested (check buildenv and PKGBUILD opts)
// 	if check_buildoption "ccache" "y" && [[ -d /usr/lib/ccache/bin ]]; then
// 		export PATH="/usr/lib/ccache/bin:$PATH"
// 		ccache=1
// 	fi

// 	# use distcc if it is requested (check buildenv and PKGBUILD opts)
// 	if check_buildoption "distcc" "y"; then
// 		if (( ccache )); then
// 			export CCACHE_PREFIX="${CCACHE_PREFIX:+$CCACHE_PREFIX }distcc"
// 			export CCACHE_BASEDIR="$srcdir"
// 		elif [[ -d /usr/lib/distcc/bin ]]; then
// 			export PATH="/usr/lib/distcc/bin:$PATH"
// 		fi
// 		export DISTCC_HOSTS
// 	fi
// }

// run_function_safe() {
// 	local restoretrap restoreset restoreshopt

// 	# we don't set any special shopts of our own, but we don't want the user to
// 	# muck with our environment.
// 	restoreshopt=$(shopt -p)

// 	restoreset=$(shopt -o -p)
// 	shopt -o -s errexit errtrace

// 	restoretrap=$(trap -p ERR)
// 	trap "error_function '$1'" ERR

// 	run_function "$1"

// 	eval "$restoretrap"
// 	eval "$restoreset"
// 	eval "$restoreshopt"
// }

// run_function() {
// 	if [[ -z $1 ]]; then
// 		return 1
// 	fi
// 	local pkgfunc="$1"

// 	msg "$(gettext "Starting %s()...")" "$pkgfunc"
// 	cd_safe "$srcdir"

// 	# save our shell options so pkgfunc() can't override what we need
// 	local shellopts=$(shopt -p)

// 	local ret=0
// 	if (( LOGGING )); then
// 		local fullver=$(get_full_version)
// 		local BUILDLOG="$LOGDEST/${pkgbase}-${fullver}-${CARCH}-$pkgfunc.log"
// 		if [[ -f $BUILDLOG ]]; then
// 			local i=1
// 			while true; do
// 				if [[ -f $BUILDLOG.$i ]]; then
// 					i=$(($i +1))
// 				else
// 					break
// 				fi
// 			done
// 			mv "$BUILDLOG" "$BUILDLOG.$i"
// 		fi

// 		# ensure overridden package variables survive tee with split packages
// 		logpipe=$(mktemp -u "$LOGDEST/logpipe.XXXXXXXX")
// 		mkfifo "$logpipe"
// 		tee "$BUILDLOG" < "$logpipe" &
// 		local teepid=$!

// 		$pkgfunc &>"$logpipe"

// 		wait $teepid
// 		rm "$logpipe"
// 	else
// 		"$pkgfunc"
// 	fi
// 	# reset our shell options
// 	eval "$shellopts"
// }

// run_prepare() {
// 	run_function_safe "prepare"
// }

// run_build() {
// 	run_function_safe "build"
// }

// run_check() {
// 	run_function_safe "check"
// }

// run_package() {
// 	local pkgfunc
// 	if [[ -z $1 ]]; then
// 		pkgfunc="package"
// 	else
// 		pkgfunc="package_$1"
// 	fi

// 	run_function_safe "$pkgfunc"
// }

// find_libdepends() {
// 	local d sodepends;

// 	sodepends=0;
// 	for d in "${depends[@]}"; do
// 		if [[ $d = *.so ]]; then
// 			sodepends=1;
// 			break;
// 		fi
// 	done

// 	if (( sodepends == 0 )); then
// 		(( ${#depends[@]} )) && printf '%s\n' "${depends[@]}"
// 		return;
// 	fi

// 	local libdeps filename soarch sofile soname soversion;
// 	declare -A libdeps;

// 	while read -r filename; do
// 		# get architecture of the file; if soarch is empty it's not an ELF binary
// 		soarch=$(LC_ALL=C readelf -h "$filename" 2>/dev/null | sed -n 's/.*Class.*ELF\(32\|64\)/\1/p')
// 		[[ -n "$soarch" ]] || continue

// 		# process all libraries needed by the binary
// 		for sofile in $(LC_ALL=C readelf -d "$filename" 2>/dev/null | sed -nr 's/.*Shared library: \[(.*)\].*/\1/p')
// 		do
// 			# extract the library name: libfoo.so
// 			soname="${sofile%.so?(+(.+([0-9])))}".so
// 			# extract the major version: 1
// 			soversion="${sofile##*\.so\.}"

// 			if [[ ${libdeps[$soname]} ]]; then
// 				if [[ ${libdeps[$soname]} != *${soversion}-${soarch}* ]]; then
// 					libdeps[$soname]+=" ${soversion}-${soarch}"
// 				fi
// 			else
// 				libdeps[$soname]="${soversion}-${soarch}"
// 			fi
// 		done
// 	done < <(find "$pkgdir" -type f -perm -u+x)

// 	local libdepends v
// 	for d in "${depends[@]}"; do
// 		case "$d" in
// 			*.so)
// 				if [[ ${libdeps[$d]} ]]; then
// 					for v in ${libdeps[$d]}; do
// 						libdepends+=("$d=$v")
// 					done
// 				else
// 					warning "$(gettext "Library listed in %s is not required by any files: %s")" "'depends'" "$d"
// 					libdepends+=("$d")
// 				fi
// 				;;
// 			*)
// 				libdepends+=("$d")
// 				;;
// 		esac
// 	done

// 	(( ${#libdepends[@]} )) && printf '%s\n' "${libdepends[@]}"
// }


// find_libprovides() {
// 	local p libprovides missing
// 	for p in "${provides[@]}"; do
// 		missing=0
// 		case "$p" in
// 			*.so)
// 				mapfile -t filename < <(find "$pkgdir" -type f -name $p\*)
// 				if [[ $filename ]]; then
// 					# packages may provide multiple versions of the same library
// 					for fn in "${filename[@]}"; do
// 						# check if we really have a shared object
// 						if LC_ALL=C readelf -h "$fn" 2>/dev/null | grep -q '.*Type:.*DYN (Shared object file).*'; then
// 							# get the string binaries link to (e.g. libfoo.so.1.2 -> libfoo.so.1)
// 							local sofile=$(LC_ALL=C readelf -d "$fn" 2>/dev/null | sed -n 's/.*Library soname: \[\(.*\)\].*/\1/p')
// 							if [[ -z "$sofile" ]]; then
// 								warning "$(gettext "Library listed in %s is not versioned: %s")" "'provides'" "$p"
// 								libprovides+=("$p")
// 								continue
// 							fi

// 							# get the library architecture (32 or 64 bit)
// 							local soarch=$(LC_ALL=C readelf -h "$fn" | sed -n 's/.*Class.*ELF\(32\|64\)/\1/p')

// 							# extract the library major version
// 							local soversion="${sofile##*\.so\.}"

// 							libprovides+=("${p}=${soversion}-${soarch}")
// 						else
// 							warning "$(gettext "Library listed in %s is not a shared object: %s")" "'provides'" "$p"
// 							libprovides+=("$p")
// 						fi
// 					done
// 				else
// 					libprovides+=("$p")
// 					missing=1
// 				fi
// 				;;
// 			*)
// 				libprovides+=("$p")
// 				;;
// 		esac

// 		if (( missing )); then
// 			warning "$(gettext "Cannot find library listed in %s: %s")" "'provides'" "$p"
// 		fi
// 	done

// 	(( ${#libprovides[@]} )) && printf '%s\n' "${libprovides[@]}"
// }

// write_kv_pair() {
// 	local key="$1"
// 	shift

// 	for val in "$@"; do
// 		if [[ $val = *$'\n'* ]]; then
// 			error "$(gettext "Invalid value for %s: %s")" "$key" "$val"
// 			exit 1
// 		fi
// 		printf "%s = %s\n" "$key" "$val"
// 	done
// }

// write_pkginfo() {
// 	local size="$(@DUPATH@ @DUFLAGS@)"
// 	size="$(( ${size%%[^0-9]*} * 1024 ))"

// 	merge_arch_attrs

// 	msg2 "$(gettext "Generating %s file...")" ".PKGINFO"
// 	printf "# Generated by makepkg %s\n" "$makepkg_version"
// 	printf "# using %s\n" "$(fakeroot -v)"

// 	write_kv_pair "pkgname" "$pkgname"
// 	write_kv_pair "pkgbase" "$pkgbase"

// 	local fullver=$(get_full_version)
// 	write_kv_pair "pkgver" "$fullver"

// 	# TODO: all fields should have this treatment
// 	local spd="${pkgdesc//+([[:space:]])/ }"
// 	spd=("${spd[@]#[[:space:]]}")
// 	spd=("${spd[@]%[[:space:]]}")

// 	write_kv_pair "pkgdesc" "$spd"
// 	write_kv_pair "url" "$url"
// 	write_kv_pair "builddate" "$SOURCE_DATE_EPOCH"
// 	write_kv_pair "packager" "$PACKAGER"
// 	write_kv_pair "size" "$size"
// 	write_kv_pair "arch" "$pkgarch"

// 	mapfile -t provides < <(find_libprovides)
// 	mapfile -t depends < <(find_libdepends)

// 	write_kv_pair "license"     "${license[@]}"
// 	write_kv_pair "replaces"    "${replaces[@]}"
// 	write_kv_pair "group"       "${groups[@]}"
// 	write_kv_pair "conflict"    "${conflicts[@]}"
// 	write_kv_pair "provides"    "${provides[@]}"
// 	write_kv_pair "backup"      "${backup[@]}"
// 	write_kv_pair "depend"      "${depends[@]}"
// 	write_kv_pair "optdepend"   "${optdepends[@]//+([[:space:]])/ }"
// 	write_kv_pair "makedepend"  "${makedepends[@]}"
// 	write_kv_pair "checkdepend" "${checkdepends[@]}"
// }

// write_buildinfo() {
// 	msg2 "$(gettext "Generating %s file...")" ".BUILDINFO"

// 	write_kv_pair "format" "1"

// 	write_kv_pair "pkgname" "$pkgname"
// 	write_kv_pair "pkgbase" "$pkgbase"

// 	local fullver=$(get_full_version)
// 	write_kv_pair "pkgver" "$fullver"

// 	local sum="$(sha256sum "${BUILDFILE}")"
// 	sum=${sum%% *}
// 	write_kv_pair "pkgbuild_sha256sum" $sum

// 	write_kv_pair "packager" "${PACKAGER}"
// 	write_kv_pair "builddate" "${SOURCE_DATE_EPOCH}"
// 	write_kv_pair "builddir"  "${BUILDDIR}"
// 	write_kv_pair "buildenv" "${BUILDENV[@]}"
// 	write_kv_pair "options" "${OPTIONS[@]}"

// 	local pkglist=($(run_pacman -Q | sed "s# #-#"))
// 	write_kv_pair "installed" "${pkglist[@]}"
// }

// # build a sorted NUL-separated list of the full contents of the current
// # directory suitable for passing to `bsdtar --files-from`
// # database files are placed at the beginning of the package regardless of
// # sorting
// list_package_files() {
// 	(find . -path './.*' \! -name '.'; find . \! -path './.*' \! -name '.' | LC_ALL=C sort) |
// 	sed -e 's|^\./||' | tr '\n' '\0'
// }

// create_package() {
// 	(( NOARCHIVE )) && return

// 	if [[ ! -d $pkgdir ]]; then
// 		error "$(gettext "Missing %s directory.")" "\$pkgdir/"
// 		plain "$(gettext "Aborting...")"
// 		exit 1 # $E_MISSING_PKGDIR
// 	fi

// 	cd_safe "$pkgdir"
// 	msg "$(gettext "Creating package \"%s\"...")" "$pkgname"

// 	pkgarch=$(get_pkg_arch)
// 	write_pkginfo > .PKGINFO
// 	write_buildinfo > .BUILDINFO

// 	# check for changelog/install files
// 	for i in 'changelog/.CHANGELOG' 'install/.INSTALL'; do
// 		IFS='/' read -r orig dest < <(printf '%s\n' "$i")

// 		if [[ -n ${!orig} ]]; then
// 			msg2 "$(gettext "Adding %s file...")" "$orig"
// 			if ! cp "$startdir/${!orig}" "$dest"; then
// 				error "$(gettext "Failed to add %s file to package.")" "$orig"
// 				exit 1
// 			fi
// 			chmod 644 "$dest"
// 		fi
// 	done

// 	# tar it up
// 	local fullver=$(get_full_version)
// 	local pkg_file="$PKGDEST/${pkgname}-${fullver}-${pkgarch}${PKGEXT}"
// 	local ret=0

// 	[[ -f $pkg_file ]] && rm -f "$pkg_file"
// 	[[ -f $pkg_file.sig ]] && rm -f "$pkg_file.sig"

// 	# ensure all elements of the package have the same mtime
// 	find . -exec touch -h -d @$SOURCE_DATE_EPOCH {} +

// 	msg2 "$(gettext "Generating .MTREE file...")"
// 	list_package_files | LANG=C bsdtar -cnf - --format=mtree \
// 		--options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' \
// 		--null --files-from - --exclude .MTREE | gzip -c -f -n > .MTREE
// 	touch -d @$SOURCE_DATE_EPOCH .MTREE

// 	msg2 "$(gettext "Compressing package...")"
// 	# TODO: Maybe this can be set globally for robustness
// 	shopt -s -o pipefail
// 	# bsdtar's gzip compression always saves the time stamp, making one
// 	# archive created using the same command line distinct from another.
// 	# Disable bsdtar compression and use gzip -n for now.
// 	list_package_files | LANG=C bsdtar -cnf - --null --files-from - |
// 	case "$PKGEXT" in
// 		*tar.gz)  ${COMPRESSGZ[@]:-gzip -c -f -n} ;;
// 		*tar.bz2) ${COMPRESSBZ2[@]:-bzip2 -c -f} ;;
// 		*tar.xz)  ${COMPRESSXZ[@]:-xz -c -z -} ;;
// 		*tar.lrz) ${COMPRESSLRZ[@]:-lrzip -q} ;;
// 		*tar.lzo) ${COMPRESSLZO[@]:-lzop -q} ;;
// 		*tar.Z)   ${COMPRESSZ[@]:-compress -c -f} ;;
// 		*tar)     cat ;;
// 		*) warning "$(gettext "'%s' is not a valid archive extension.")" \
// 			"$PKGEXT"; cat ;;
// 	esac > "${pkg_file}" || ret=$?

// 	shopt -u -o pipefail

// 	if (( ret )); then
// 		error "$(gettext "Failed to create package file.")"
// 		exit 1 # TODO: error code
// 	fi
// }

// create_debug_package() {
// 	# check if a debug package was requested
// 	if ! check_option "debug" "y" || ! check_option "strip" "y"; then
// 		return
// 	fi

// 	pkgdir="$pkgdirbase/$pkgbase-@DEBUGSUFFIX@"

// 	# check if we have any debug symbols to package
// 	if dir_is_empty "$pkgdir/usr/lib/debug"; then
// 		return
// 	fi

// 	unset groups depends optdepends provides conflicts replaces backup install changelog

// 	local pkg
// 	for pkg in ${pkgname[@]}; do
// 		if [[ $pkg != $pkgbase ]]; then
// 			provides+=("$pkg-@DEBUGSUFFIX@")
// 		fi
// 	done

// 	pkgdesc="Detached debugging symbols for $pkgname"
// 	pkgname=$pkgbase-@DEBUGSUFFIX@

// 	create_package
// }

// create_srcpackage() {
// 	local ret=0
// 	msg "$(gettext "Creating source package...")"
// 	local srclinks="$(mktemp -d "$startdir"/srclinks.XXXXXXXXX)"
// 	mkdir "${srclinks}"/${pkgbase}

// 	msg2 "$(gettext "Adding %s...")" "$BUILDSCRIPT"
// 	ln -s "${BUILDFILE}" "${srclinks}/${pkgbase}/${BUILDSCRIPT}"

// 	msg2 "$(gettext "Generating %s file...")" .SRCINFO
// 	write_srcinfo > "$srclinks/$pkgbase"/.SRCINFO

// 	local file all_sources

// 	get_all_sources 'all_sources'
// 	for file in "${all_sources[@]}"; do
// 		if [[ "$file" = "$(get_filename "$file")" ]] || (( SOURCEONLY == 2 )); then
// 			local absfile
// 			absfile=$(get_filepath "$file") || missing_source_file "$file"
// 			msg2 "$(gettext "Adding %s...")" "${absfile##*/}"
// 			ln -s "$absfile" "$srclinks/$pkgbase"
// 		fi
// 	done

// 	local i
// 	for i in 'changelog' 'install'; do
// 		local file files

// 		[[ ${!i} ]] && files+=("${!i}")
// 		for name in "${pkgname[@]}"; do
// 			if extract_function_variable "package_$name" "$i" 0 file; then
// 				files+=("$file")
// 			fi
// 		done

// 		for file in "${files[@]}"; do
// 			if [[ $file && ! -f "${srclinks}/${pkgbase}/$file" ]]; then
// 				msg2 "$(gettext "Adding %s file (%s)...")" "$i" "${file}"
// 				ln -s "${startdir}/$file" "${srclinks}/${pkgbase}/"
// 			fi
// 		done
// 	done

// 	local TAR_OPT
// 	case "$SRCEXT" in
// 		*tar.gz)  TAR_OPT="-z" ;;
// 		*tar.bz2) TAR_OPT="-j" ;;
// 		*tar.xz)  TAR_OPT="-J" ;;
// 		*tar.lrz) TAR_OPT="--lrzip" ;;
// 		*tar.lzo) TAR_OPT="--lzop" ;;
// 		*tar.Z)   TAR_OPT="-Z" ;;
// 		*tar)     TAR_OPT=""  ;;
// 		*) warning "$(gettext "'%s' is not a valid archive extension.")" \
// 		"$SRCEXT" ;;
// 	esac

// 	local fullver=$(get_full_version)
// 	local pkg_file="$SRCPKGDEST/${pkgbase}-${fullver}${SRCEXT}"

// 	# tar it up
// 	msg2 "$(gettext "Compressing source package...")"
// 	cd_safe "${srclinks}"
// 	if ! LANG=C bsdtar -cL ${TAR_OPT} -f "$pkg_file" ${pkgbase}; then
// 		error "$(gettext "Failed to create source package file.")"
// 		exit 1 # TODO: error code
// 	fi

// 	cd_safe "${startdir}"
// 	rm -rf "${srclinks}"
// }

// # this function always returns 0 to make sure clean-up will still occur
// install_package() {
// 	(( ! INSTALL )) && return

// 	if (( ! SPLITPKG )); then
// 		msg "$(gettext "Installing package %s with %s...")" "$pkgname" "$PACMAN -U"
// 	else
// 		msg "$(gettext "Installing %s package group with %s...")" "$pkgbase" "$PACMAN -U"
// 	fi

// 	local fullver pkgarch pkg pkglist
// 	(( ASDEPS )) && pkglist+=('--asdeps')
// 	(( NEEDED )) && pkglist+=('--needed')

// 	for pkg in ${pkgname[@]}; do
// 		fullver=$(get_full_version)
// 		pkgarch=$(get_pkg_arch $pkg)
// 		pkglist+=("$PKGDEST/${pkg}-${fullver}-${pkgarch}${PKGEXT}")

// 		if [[ -f "$PKGDEST/${pkg}-@DEBUGSUFFIX@-${fullver}-${pkgarch}${PKGEXT}" ]]; then
// 			pkglist+=("$PKGDEST/${pkg}-@DEBUGSUFFIX@-${fullver}-${pkgarch}${PKGEXT}")
// 		fi
// 	done

// 	if ! run_pacman -U "${pkglist[@]}"; then
// 		warning "$(gettext "Failed to install built package(s).")"
// 		return 0
// 	fi
// }

// get_vcsclient() {
// 	local proto=${1%%+*}

// 	local i
// 	for i in "${VCSCLIENTS[@]}"; do
// 		local handler="${i%%::*}"
// 		if [[ $proto = "$handler" ]]; then
// 			local client="${i##*::}"
// 			break
// 		fi
// 	done

// 	# if we didn't find an client, return an error
// 	if [[ -z $client ]]; then
// 		error "$(gettext "Unknown download protocol: %s")" "$proto"
// 		plain "$(gettext "Aborting...")"
// 		exit 1 # $E_CONFIG_ERROR
// 	fi

// 	printf "%s\n" "$client"
// }

// check_vcs_software() {
// 	local all_sources all_deps deps ret=0

// 	if (( SOURCEONLY == 1 )); then
// 		# we will not download VCS sources
// 		return $ret
// 	fi

// 	if [[ -z $PACMAN_PATH ]]; then
// 		warning "$(gettext "Cannot find the %s binary needed to check VCS source requirements.")" "$PACMAN"
// 		return $ret
// 	fi

// 	# we currently only use global depends/makedepends arrays for --syncdeps
// 	for attr in depends makedepends; do
// 		get_pkgbuild_attribute "$pkg" "$attr" 1 'deps'
// 		all_deps+=("${deps[@]}")

// 		get_pkgbuild_attribute "$pkg" "${attr}_$CARCH" 1 'deps'
// 		all_deps+=("${deps[@]}")
// 	done

// 	get_all_sources_for_arch 'all_sources'
// 	for netfile in ${all_sources[@]}; do
// 		local proto=$(get_protocol "$netfile")

// 		case $proto in
// 			bzr*|git*|hg*|svn*)
// 				if ! type -p ${proto%%+*} > /dev/null; then
// 					local client
// 					client=$(get_vcsclient "$proto") || exit $?
// 					# ensure specified program is installed
// 					local uninstalled
// 					uninstalled=$(check_deps "$client") || exit 1
// 					# if not installed, check presence in depends or makedepends
// 					if [[ -n "$uninstalled" ]] && (( ! NODEPS || ( VERIFYSOURCE && !DEP_BIN ) )); then
// 						if ! in_array "$client" ${all_deps[@]}; then
// 							error "$(gettext "Cannot find the %s package needed to handle %s sources.")" \
// 									"$client" "${proto%%+*}"
// 							ret=1
// 						fi
// 					fi
// 				fi
// 				;;
// 			*)
// 				# non VCS source
// 				;;
// 		esac
// 	done

// 	return $ret
// }

// check_software() {
// 	# check for needed software
// 	local ret=0

// 	# check for PACMAN if we need it
// 	if (( ! NODEPS || DEP_BIN || RMDEPS || INSTALL )); then
// 		if [[ -z $PACMAN_PATH ]]; then
// 			error "$(gettext "Cannot find the %s binary required for dependency operations.")" "$PACMAN"
// 			ret=1
// 		fi
// 	fi

// 	# check for sudo if we will need it during makepkg execution
// 	if (( DEP_BIN || RMDEPS || INSTALL )); then
// 		if ! type -p sudo >/dev/null; then
// 			warning "$(gettext "Cannot find the %s binary. Will use %s to acquire root privileges.")" "sudo" "su"
// 		fi
// 	fi

// 	# fakeroot - correct package file permissions
// 	if check_buildenv "fakeroot" "y" && (( EUID > 0 )); then
// 		if ! type -p fakeroot >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary.")" "fakeroot"
// 			ret=1
// 		fi
// 	fi

// 	# gpg - package signing
// 	if [[ $SIGNPKG == 'y' ]] || { [[ -z $SIGNPKG ]] && check_buildenv "sign" "y"; }; then
// 		if ! type -p gpg >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for signing packages.")" "gpg"
// 			ret=1
// 		fi
// 	fi

// 	# gpg - source verification
// 	if (( ! SKIPPGPCHECK )) && source_has_signatures; then
// 		if ! type -p gpg >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for verifying source files.")" "gpg"
// 			ret=1
// 		fi
// 	fi

// 	# checksum operations
// 	if (( GENINTEG || ! SKIPCHECKSUMS )); then
// 		local integlist
// 		IFS=$'\n' read -rd '' -a integlist < <(get_integlist)

// 		local integ
// 		for integ in "${integlist[@]}"; do
// 			if ! type -p "${integ}sum" >/dev/null; then
// 				error "$(gettext "Cannot find the %s binary required for source file checksums operations.")" "${integ}sum"
// 				ret=1
// 			fi
// 		done
// 	fi

// 	# distcc - compilation with distcc
// 	if check_buildoption "distcc" "y"; then
// 		if ! type -p distcc >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for distributed compilation.")" "distcc"
// 			ret=1
// 		fi
// 	fi

// 	# ccache - compilation with ccache
// 	if check_buildoption "ccache" "y"; then
// 		if ! type -p ccache >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for compiler cache usage.")" "ccache"
// 			ret=1
// 		fi
// 	fi

// 	# strip - strip symbols from binaries/libraries
// 	if check_option "strip" "y"; then
// 		if ! type -p strip >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for object file stripping.")" "strip"
// 			ret=1
// 		fi
// 	fi

// 	# gzip - compressig man and info pages
// 	if check_option "zipman" "y"; then
// 		if ! type -p gzip >/dev/null; then
// 			error "$(gettext "Cannot find the %s binary required for compressing man and info pages.")" "gzip"
// 			ret=1
// 		fi
// 	fi

// 	# tools to download vcs sources
// 	if ! check_vcs_software; then
// 		ret=1
// 	fi

// 	return $ret
// }

// check_build_status() {
// 	if (( ! SPLITPKG )); then
// 		fullver=$(get_full_version)
// 		pkgarch=$(get_pkg_arch)
// 		if [[ -f $PKGDEST/${pkgname}-${fullver}-${pkgarch}${PKGEXT} ]] \
// 				 && ! (( FORCE || SOURCEONLY || NOBUILD || NOARCHIVE)); then
// 			if (( INSTALL )); then
// 				warning "$(gettext "A package has already been built, installing existing package...")"
// 				install_package
// 				exit 0
// 			else
// 				error "$(gettext "A package has already been built. (use %s to overwrite)")" "-f"
// 				exit 1
// 			fi
// 		fi
// 	else
// 		allpkgbuilt=1
// 		somepkgbuilt=0
// 		for pkg in ${pkgname[@]}; do
// 			fullver=$(get_full_version)
// 			pkgarch=$(get_pkg_arch $pkg)
// 			if [[ -f $PKGDEST/${pkg}-${fullver}-${pkgarch}${PKGEXT} ]]; then
// 				somepkgbuilt=1
// 			else
// 				allpkgbuilt=0
// 			fi
// 		done
// 		if ! (( FORCE || SOURCEONLY || NOBUILD || NOARCHIVE)); then
// 			if (( allpkgbuilt )); then
// 				if (( INSTALL )); then
// 					warning "$(gettext "The package group has already been built, installing existing packages...")"
// 					install_package
// 					exit 0
// 				else
// 					error "$(gettext "The package group has already been built. (use %s to overwrite)")" "-f"
// 					exit 1
// 				fi
// 			fi
// 			if (( somepkgbuilt && ! PKGVERFUNC )); then
// 				error "$(gettext "Part of the package group has already been built. (use %s to overwrite)")" "-f"
// 				exit 1
// 			fi
// 		fi
// 		unset allpkgbuilt somepkgbuilt
// 	fi
// }

// backup_package_variables() {
// 	local var
// 	for var in ${splitpkg_overrides[@]}; do
// 		local indirect="${var}_backup"
// 		eval "${indirect}=(\"\${$var[@]}\")"
// 	done
// }

// restore_package_variables() {
// 	local var
// 	for var in ${splitpkg_overrides[@]}; do
// 		local indirect="${var}_backup"
// 		if [[ -n ${!indirect} ]]; then
// 			eval "${var}=(\"\${$indirect[@]}\")"
// 		else
// 			unset ${var}
// 		fi
// 	done
// }

// run_split_packaging() {
// 	local pkgname_backup=("${pkgname[@]}")
// 	for pkgname in ${pkgname_backup[@]}; do
// 		pkgdir="$pkgdirbase/$pkgname"
// 		mkdir "$pkgdir"
// 		backup_package_variables
// 		run_package $pkgname
// 		tidy_install
// 		lint_package || exit 1
// 		create_package
// 		restore_package_variables
// 	done
// 	pkgname=("${pkgname_backup[@]}")
// 	create_debug_package
// }

// usage() {
// 	printf "makepkg (pacman) %s\n" "$makepkg_version"
// 	echo
// 	printf -- "$(gettext "Make packages compatible for use with pacman")\n"
// 	echo
// 	printf -- "$(gettext "Usage: %s [options]")\n" "$0"
// 	echo
// 	printf -- "$(gettext "Options:")\n"
// 	printf -- "$(gettext "  -A, --ignorearch Ignore incomplete %s field in %s")\n" "arch" "$BUILDSCRIPT"
// 	printf -- "$(gettext "  -c, --clean      Clean up work files after build")\n"
// 	printf -- "$(gettext "  -C, --cleanbuild Remove %s dir before building the package")\n" "\$srcdir/"
// 	printf -- "$(gettext "  -d, --nodeps     Skip all dependency checks")\n"
// 	printf -- "$(gettext "  -e, --noextract  Do not extract source files (use existing %s dir)")\n" "\$srcdir/"
// 	printf -- "$(gettext "  -f, --force      Overwrite existing package")\n"
// 	printf -- "$(gettext "  -g, --geninteg   Generate integrity checks for source files")\n"
// 	printf -- "$(gettext "  -h, --help       Show this help message and exit")\n"
// 	printf -- "$(gettext "  -i, --install    Install package after successful build")\n"
// 	printf -- "$(gettext "  -L, --log        Log package build process")\n"
// 	printf -- "$(gettext "  -m, --nocolor    Disable colorized output messages")\n"
// 	printf -- "$(gettext "  -o, --nobuild    Download and extract files only")\n"
// 	printf -- "$(gettext "  -p <file>        Use an alternate build script (instead of '%s')")\n" "$BUILDSCRIPT"
// 	printf -- "$(gettext "  -r, --rmdeps     Remove installed dependencies after a successful build")\n"
// 	printf -- "$(gettext "  -R, --repackage  Repackage contents of the package without rebuilding")\n"
// 	printf -- "$(gettext "  -s, --syncdeps   Install missing dependencies with %s")\n" "pacman"
// 	printf -- "$(gettext "  -S, --source     Generate a source-only tarball without downloaded sources")\n"
// 	printf -- "$(gettext "  -V, --version    Show version information and exit")\n"
// 	printf -- "$(gettext "  --allsource      Generate a source-only tarball including downloaded sources")\n"
// 	printf -- "$(gettext "  --check          Run the %s function in the %s")\n" "check()" "$BUILDSCRIPT"
// 	printf -- "$(gettext "  --config <file>  Use an alternate config file (instead of '%s')")\n" "$confdir/makepkg.conf"
// 	printf -- "$(gettext "  --holdver        Do not update VCS sources")\n"
// 	printf -- "$(gettext "  --key <key>      Specify a key to use for %s signing instead of the default")\n" "gpg"
// 	printf -- "$(gettext "  --noarchive      Do not create package archive")\n"
// 	printf -- "$(gettext "  --nocheck        Do not run the %s function in the %s")\n" "check()" "$BUILDSCRIPT"
// 	printf -- "$(gettext "  --noprepare      Do not run the %s function in the %s")\n" "prepare()" "$BUILDSCRIPT"
// 	printf -- "$(gettext "  --nosign         Do not create a signature for the package")\n"
// 	printf -- "$(gettext "  --packagelist    Only list packages that would be produced, without PKGEXT")\n"
// 	printf -- "$(gettext "  --printsrcinfo   Print the generated SRCINFO and exit")\n"
// 	printf -- "$(gettext "  --sign           Sign the resulting package with %s")\n" "gpg"
// 	printf -- "$(gettext "  --skipchecksums  Do not verify checksums of the source files")\n"
// 	printf -- "$(gettext "  --skipinteg      Do not perform any verification checks on source files")\n"
// 	printf -- "$(gettext "  --skippgpcheck   Do not verify source files with PGP signatures")\n"
// 	printf -- "$(gettext "  --verifysource   Download source files (if needed) and perform integrity checks")\n"
// 	echo
// 	printf -- "$(gettext "These options can be passed to %s:")\n" "pacman"
// 	echo
// 	printf -- "$(gettext "  --asdeps         Install packages as non-explicitly installed")\n"
// 	printf -- "$(gettext "  --needed         Do not reinstall the targets that are already up to date")\n"
// 	printf -- "$(gettext "  --noconfirm      Do not ask for confirmation when resolving dependencies")\n"
// 	printf -- "$(gettext "  --noprogressbar  Do not show a progress bar when downloading files")\n"
// 	echo
// 	printf -- "$(gettext "If %s is not specified, %s will look for '%s'")\n" "-p" "makepkg" "$BUILDSCRIPT"
// 	echo
// }

// version() {
// 	printf "makepkg (pacman) %s\n" "$makepkg_version"
// 	printf -- "$(gettext "\
// Copyright (c) 2006-2017 Pacman Development Team <pacman-dev@archlinux.org>.\n\
// Copyright (C) 2002-2006 Judd Vinet <jvinet@zeroflux.org>.\n\n\
// This is free software; see the source for copying conditions.\n\
// There is NO WARRANTY, to the extent permitted by law.\n")"
// }

// # PROGRAM START
fn main(){
// # ensure we have a sane umask set
// umask 0022

// # determine whether we have gettext; make it a no-op if we do not
// if ! type -p gettext >/dev/null; then
// 	gettext() {
// 		printf "%s\n" "$@"
// 	}
// fi

// ARGLIST=("$@")

// # Parse Command Line Options.
// OPT_SHORT="AcCdefFghiLmop:rRsSV"
// OPT_LONG=('allsource' 'check' 'clean' 'cleanbuild' 'config:' 'force' 'geninteg'
//           'help' 'holdver' 'ignorearch' 'install' 'key:' 'log' 'noarchive' 'nobuild'
//           'nocolor' 'nocheck' 'nodeps' 'noextract' 'noprepare' 'nosign' 'packagelist'
//           'printsrcinfo' 'repackage' 'rmdeps' 'sign' 'skipchecksums' 'skipinteg'
//           'skippgpcheck' 'source' 'syncdeps' 'verifysource' 'version')

// # Pacman Options
// OPT_LONG+=('asdeps' 'noconfirm' 'needed' 'noprogressbar')

// if ! parseopts "$OPT_SHORT" "${OPT_LONG[@]}" -- "$@"; then
// 	exit 1 # E_INVALID_OPTION;
// fi
// set -- "${OPTRET[@]}"
// unset OPT_SHORT OPT_LONG OPTRET

// while true; do
// 	case "$1" in
// 		# Pacman Options
// 		--asdeps)         ASDEPS=1;;
// 		--needed)         NEEDED=1;;
// 		--noconfirm)      PACMAN_OPTS+=("--noconfirm") ;;
// 		--noprogressbar)  PACMAN_OPTS+=("--noprogressbar") ;;

// 		# Makepkg Options
// 		--allsource)      SOURCEONLY=2 ;;
// 		-A|--ignorearch)  IGNOREARCH=1 ;;
// 		-c|--clean)       CLEANUP=1 ;;
// 		-C|--cleanbuild)  CLEANBUILD=1 ;;
// 		--check)          RUN_CHECK='y' ;;
// 		--config)         shift; MAKEPKG_CONF=$1 ;;
// 		-d|--nodeps)      NODEPS=1 ;;
// 		-e|--noextract)   NOEXTRACT=1 ;;
// 		-f|--force)       FORCE=1 ;;
// 		-F)               INFAKEROOT=1 ;;
// 		# generating integrity checks does not depend on architecture
// 		-g|--geninteg)    GENINTEG=1 IGNOREARCH=1;;
// 		--holdver)        HOLDVER=1 ;;
// 		-i|--install)     INSTALL=1 ;;
// 		--key)            shift; GPGKEY=$1 ;;
// 		-L|--log)         LOGGING=1 ;;
// 		-m|--nocolor)     USE_COLOR='n'; PACMAN_OPTS+=("--color never") ;;
// 		--noarchive)      NOARCHIVE=1 ;;
// 		--nocheck)        RUN_CHECK='n' ;;
// 		--noprepare)      RUN_PREPARE='n' ;;
// 		--nosign)         SIGNPKG='n' ;;
// 		-o|--nobuild)     NOBUILD=1 ;;
// 		-p)               shift; BUILDFILE=$1 ;;
// 		--packagelist)    PACKAGELIST=1 IGNOREARCH=1;;
// 		--printsrcinfo)   PRINTSRCINFO=1 IGNOREARCH=1;;
// 		-r|--rmdeps)      RMDEPS=1 ;;
// 		-R|--repackage)   REPKG=1 ;;
// 		--sign)           SIGNPKG='y' ;;
// 		--skipchecksums)  SKIPCHECKSUMS=1 ;;
// 		--skipinteg)      SKIPCHECKSUMS=1; SKIPPGPCHECK=1 ;;
// 		--skippgpcheck)   SKIPPGPCHECK=1;;
// 		-s|--syncdeps)    DEP_BIN=1 ;;
// 		-S|--source)      SOURCEONLY=1 ;;
// 		--verifysource)   VERIFYSOURCE=1 ;;

// 		-h|--help)        usage; exit 0 ;; # E_OK
// 		-V|--version)     version; exit 0 ;; # E_OK

// 		--)               OPT_IND=0; shift; break 2;;
// 	esac
// 	shift
// done

// # attempt to consume any extra argv as environment variables. this supports
// # overriding (e.g. CC=clang) as well as overriding (e.g. CFLAGS+=' -g').
// extra_environment=()
// while [[ $1 ]]; do
// 	if [[ $1 = [_[:alpha:]]*([[:alnum:]_])?(+)=* ]]; then
// 		extra_environment+=("$1")
// 	fi
// 	shift
// done

// # setup signal traps
// trap 'clean_up' 0
// for signal in TERM HUP QUIT; do
// 	trap "trap_exit $signal \"$(gettext "%s signal caught. Exiting...")\" \"$signal\"" "$signal"
// done
// trap 'trap_exit INT "$(gettext "Aborted by user! Exiting...")"' INT
// trap 'trap_exit USR1 "$(gettext "An unknown error has occurred. Exiting...")"' ERR

// # preserve environment variables and canonicalize path
// [[ -n ${PKGDEST} ]] && _PKGDEST=$(canonicalize_path ${PKGDEST})
// [[ -n ${SRCDEST} ]] && _SRCDEST=$(canonicalize_path ${SRCDEST})
// [[ -n ${SRCPKGDEST} ]] && _SRCPKGDEST=$(canonicalize_path ${SRCPKGDEST})
// [[ -n ${LOGDEST} ]] && _LOGDEST=$(canonicalize_path ${LOGDEST})
// [[ -n ${BUILDDIR} ]] && _BUILDDIR=$(canonicalize_path ${BUILDDIR})
// [[ -n ${PKGEXT} ]] && _PKGEXT=${PKGEXT}
// [[ -n ${SRCEXT} ]] && _SRCEXT=${SRCEXT}
// [[ -n ${GPGKEY} ]] && _GPGKEY=${GPGKEY}
// [[ -n ${PACKAGER} ]] && _PACKAGER=${PACKAGER}
// [[ -n ${CARCH} ]] && _CARCH=${CARCH}

// # default config is makepkg.conf
// MAKEPKG_CONF=${MAKEPKG_CONF:-$confdir/makepkg.conf}

// # Source the config file; fail if it is not found
// if [[ -r $MAKEPKG_CONF ]]; then
// 	source_safe "$MAKEPKG_CONF"
// else
// 	error "$(gettext "%s not found.")" "$MAKEPKG_CONF"
// 	plain "$(gettext "Aborting...")"
// 	exit 1 # $E_CONFIG_ERROR
// fi

// # Source user-specific makepkg.conf overrides, but only if no override config
// # file was specified
// XDG_PACMAN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/pacman"
// if [[ "$MAKEPKG_CONF" = "$confdir/makepkg.conf" ]]; then
// 	if [[ -r "$XDG_PACMAN_DIR/makepkg.conf" ]]; then
// 		source_safe "$XDG_PACMAN_DIR/makepkg.conf"
// 	elif [[ -r "$HOME/.makepkg.conf" ]]; then
// 		source_safe "$HOME/.makepkg.conf"
// 	fi
// fi

// # set pacman command if not already defined
// PACMAN=${PACMAN:-pacman}
// # save full path to command as PATH may change when sourcing /etc/profile
// PACMAN_PATH=$(type -P $PACMAN)

// # check if messages are to be printed using color
// if [[ -t 2 && $USE_COLOR != "n" ]] && check_buildenv "color" "y"; then
// 	colorize
// else
// 	unset ALL_OFF BOLD BLUE GREEN RED YELLOW
// fi


// # override settings with an environment variable for batch processing
// BUILDDIR=${_BUILDDIR:-$BUILDDIR}
// BUILDDIR=${BUILDDIR:-$startdir} #default to $startdir if undefined
// if [[ ! -d $BUILDDIR ]]; then
// 	if ! mkdir -p "$BUILDDIR"; then
// 		error "$(gettext "You do not have write permission to create packages in %s.")" "$BUILDDIR"
// 		plain "$(gettext "Aborting...")"
// 		exit 1
// 	fi
// 	chmod a-s "$BUILDDIR"
// fi
// if [[ ! -w $BUILDDIR ]]; then
// 	error "$(gettext "You do not have write permission to create packages in %s.")" "$BUILDDIR"
// 	plain "$(gettext "Aborting...")"
// 	exit 1
// fi

// # override settings from extra variables on commandline, if any
// if (( ${#extra_environment[*]} )); then
// 	export "${extra_environment[@]}"
// fi

// PKGDEST=${_PKGDEST:-$PKGDEST}
// PKGDEST=${PKGDEST:-$startdir} #default to $startdir if undefined
// if (( ! (NOBUILD || GENINTEG) )) && [[ ! -w $PKGDEST ]]; then
// 	error "$(gettext "You do not have write permission to store packages in %s.")" "$PKGDEST"
// 	plain "$(gettext "Aborting...")"
// 	exit 1
// fi

// SRCDEST=${_SRCDEST:-$SRCDEST}
// SRCDEST=${SRCDEST:-$startdir} #default to $startdir if undefined
// if [[ ! -w $SRCDEST ]] ; then
// 	error "$(gettext "You do not have write permission to store downloads in %s.")" "$SRCDEST"
// 	plain "$(gettext "Aborting...")"
// 	exit 1
// fi

// SRCPKGDEST=${_SRCPKGDEST:-$SRCPKGDEST}
// SRCPKGDEST=${SRCPKGDEST:-$startdir} #default to $startdir if undefined
// if (( SOURCEONLY )); then
// 	if [[ ! -w $SRCPKGDEST ]]; then
// 		error "$(gettext "You do not have write permission to store source tarballs in %s.")" "$SRCPKGDEST"
// 		plain "$(gettext "Aborting...")"
// 		exit 1
// 	fi

// 	# If we're only making a source tarball, then we need to ignore architecture-
// 	# dependent behavior.
// 	IGNOREARCH=1
// fi

// LOGDEST=${_LOGDEST:-$LOGDEST}
// LOGDEST=${LOGDEST:-$startdir} #default to $startdir if undefined
// if (( LOGGING )) && [[ ! -w $LOGDEST ]]; then
// 	error "$(gettext "You do not have write permission to store logs in %s.")" "$LOGDEST"
// 	plain "$(gettext "Aborting...")"
// 	exit 1
// fi

// PKGEXT=${_PKGEXT:-$PKGEXT}
// SRCEXT=${_SRCEXT:-$SRCEXT}
// GPGKEY=${_GPGKEY:-$GPGKEY}
// PACKAGER=${_PACKAGER:-$PACKAGER}
// PACKAGER=${PACKAGER:-"Unknown Packager"} #default if undefined
// CARCH=${_CARCH:-$CARCH}

// if (( ! INFAKEROOT )); then
// 	if (( EUID == 0 )); then
// 		error "$(gettext "Running %s as root is not allowed as it can cause permanent,\n\
// catastrophic damage to your system.")" "makepkg"
// 		exit 1 # $E_USER_ABORT
// 	fi
// else
// 	if [[ -z $FAKEROOTKEY ]]; then
// 		error "$(gettext "Do not use the %s option. This option is only for use by %s.")" "'-F'" "makepkg"
// 		exit 1 # TODO: error code
// 	fi
// fi

// unset pkgname pkgbase pkgver pkgrel epoch pkgdesc url license groups provides
// unset md5sums replaces depends conflicts backup source install changelog build
// unset sha{1,224,256,384,512}sums makedepends optdepends options noextract validpgpkeys
// unset "${!makedepends_@}" "${!depends_@}" "${!source_@}" "${!checkdepends_@}"
// unset "${!optdepends_@}" "${!conflicts_@}" "${!provides_@}" "${!replaces_@}"
// unset "${!md5sums_@}" "${!sha1sums_@}" "${!sha224sums_@}" "${!sha256sums_@}"
// unset "${!sha384sums_@}" "${!sha512sums_@}"

// BUILDFILE=${BUILDFILE:-$BUILDSCRIPT}
// if [[ ! -f $BUILDFILE ]]; then
// 	error "$(gettext "%s does not exist.")" "$BUILDFILE"
// 	exit 1
// else
// 	if [[ $(<"$BUILDFILE") = *$'\r'* ]]; then
// 		error "$(gettext "%s contains %s characters and cannot be sourced.")" "$BUILDFILE" "CRLF"
// 		exit 1
// 	fi

// 	if [[ ! $BUILDFILE -ef $PWD/${BUILDFILE##*/} ]]; then
// 		error "$(gettext "%s must be in the current working directory.")" "$BUILDFILE"
// 		exit 1
// 	fi

// 	if [[ ${BUILDFILE:0:1} != "/" ]]; then
// 		BUILDFILE="$startdir/$BUILDFILE"
// 	fi
// 	source_buildfile "$BUILDFILE"
// fi

// pkgbase=${pkgbase:-${pkgname[0]}}

// # check the PKGBUILD for some basic requirements
// lint_pkgbuild || exit 1

// if (( !SOURCEONLY && !PRINTSRCINFO )); then
// 	merge_arch_attrs
// fi

// basever=$(get_full_version)

// if [[ $BUILDDIR = "$startdir" ]]; then
// 	srcdir="$BUILDDIR/src"
// 	pkgdirbase="$BUILDDIR/pkg"
// else
// 	srcdir="$BUILDDIR/$pkgbase/src"
// 	pkgdirbase="$BUILDDIR/$pkgbase/pkg"

// fi

// # set pkgdir to something "sensible" for (not recommended) use during build()
// pkgdir="$pkgdirbase/$pkgbase"

// if (( GENINTEG )); then
// 	mkdir -p "$srcdir"
// 	chmod a-s "$srcdir"
// 	cd_safe "$srcdir"
// 	download_sources novcs allarch
// 	generate_checksums
// 	exit 0 # $E_OK
// fi

// if have_function pkgver; then
// 	PKGVERFUNC=1
// fi

// # check we have the software required to process the PKGBUILD
// check_software || exit 1

// if (( ${#pkgname[@]} > 1 )); then
// 	SPLITPKG=1
// fi

// # test for available PKGBUILD functions
// if have_function prepare; then
// 	# "Hide" prepare() function if not going to be run
// 	if [[ $RUN_PREPARE != "n" ]]; then
// 		PREPAREFUNC=1
// 	fi
// fi
// if have_function build; then
// 	BUILDFUNC=1
// fi
// if have_function check; then
// 	# "Hide" check() function if not going to be run
// 	if [[ $RUN_CHECK = 'y' ]] || { ! check_buildenv "check" "n" && [[ $RUN_CHECK != "n" ]]; }; then
// 		CHECKFUNC=1
// 	fi
// fi
// if have_function package; then
// 	PKGFUNC=1
// elif [[ $SPLITPKG -eq 0 ]] && have_function package_${pkgname}; then
// 	SPLITPKG=1
// fi

// # check if gpg signature is to be created and if signing key is valid
// if { [[ -z $SIGNPKG ]] && check_buildenv "sign" "y"; } || [[ $SIGNPKG == 'y' ]]; then
// 	SIGNPKG='y'
// 	if ! gpg --list-key ${GPGKEY} &>/dev/null; then
// 		if [[ ! -z $GPGKEY ]]; then
// 			error "$(gettext "The key %s does not exist in your keyring.")" "${GPGKEY}"
// 		else
// 			error "$(gettext "There is no key in your keyring.")"
// 		fi
// 		exit 1
// 	fi
// fi

// if (( PACKAGELIST )); then
// 	print_all_package_names
// 	exit 0
// fi

// if (( PRINTSRCINFO )); then
// 	write_srcinfo_content
// 	exit 0
// fi

// if (( ! PKGVERFUNC )); then
// 	check_build_status
// fi

// # Run the bare minimum in fakeroot
// if (( INFAKEROOT )); then
// 	if (( SOURCEONLY )); then
// 		create_srcpackage
// 		msg "$(gettext "Leaving %s environment.")" "fakeroot"
// 		exit 0 # $E_OK
// 	fi

// 	prepare_buildenv

// 	chmod 755 "$pkgdirbase"
// 	if (( ! SPLITPKG )); then
// 		pkgdir="$pkgdirbase/$pkgname"
// 		mkdir "$pkgdir"
// 		if (( PKGFUNC )); then
// 			run_package
// 		fi
// 		tidy_install
// 		lint_package || exit 1
// 		create_package
// 		create_debug_package
// 	else
// 		run_split_packaging
// 	fi

// 	msg "$(gettext "Leaving %s environment.")" "fakeroot"
// 	exit 0 # $E_OK
// fi

// msg "$(gettext "Making package: %s")" "$pkgbase $basever ($(date))"

// # if we are creating a source-only package, go no further
// if (( SOURCEONLY )); then
// 	if [[ -f $SRCPKGDEST/${pkgbase}-${basever}${SRCEXT} ]] \
// 			&& (( ! FORCE )); then
// 		error "$(gettext "A source package has already been built. (use %s to overwrite)")" "-f"
// 		exit 1
// 	fi

// 	# Get back to our src directory so we can begin with sources.
// 	mkdir -p "$srcdir"
// 	chmod a-s "$srcdir"
// 	cd_safe "$srcdir"
// 	if (( SOURCEONLY == 2 )); then
// 		download_sources allarch
// 	elif ( (( ! SKIPCHECKSUMS )) || \
// 			( (( ! SKIPPGPCHECK )) && source_has_signatures ) ); then
// 		download_sources allarch novcs
// 	fi
// 	check_source_integrity all
// 	cd_safe "$startdir"

// 	enter_fakeroot

// 	msg "$(gettext "Signing package...")"
// 	create_signature "$SRCPKGDEST/${pkgbase}-${fullver}${SRCEXT}"

// 	msg "$(gettext "Source package created: %s")" "$pkgbase ($(date))"
// 	exit 0
// fi

// if (( NODEPS || ( VERIFYSOURCE && !DEP_BIN ) )); then
// 	if (( NODEPS )); then
// 		warning "$(gettext "Skipping dependency checks.")"
// 	fi
// else
// 	if (( RMDEPS && ! INSTALL )); then
// 		original_pkglist=($(run_pacman -Qq))    # required by remove_dep
// 	fi
// 	deperr=0

// 	msg "$(gettext "Checking runtime dependencies...")"
// 	resolve_deps ${depends[@]} || deperr=1

// 	if (( RMDEPS && INSTALL )); then
// 		original_pkglist=($(run_pacman -Qq))    # required by remove_dep
// 	fi

// 	msg "$(gettext "Checking buildtime dependencies...")"
// 	if (( CHECKFUNC )); then
// 		resolve_deps "${makedepends[@]}" "${checkdepends[@]}" || deperr=1
// 	else
// 		resolve_deps "${makedepends[@]}" || deperr=1
// 	fi

// 	if (( RMDEPS )); then
// 		current_pkglist=($(run_pacman -Qq))    # required by remove_deps
// 	fi

// 	if (( deperr )); then
// 		error "$(gettext "Could not resolve all dependencies.")"
// 		exit 1
// 	fi
// fi

// # get back to our src directory so we can begin with sources
// mkdir -p "$srcdir"
// chmod a-s "$srcdir"
// cd_safe "$srcdir"

// if (( !REPKG )); then
// 	if (( NOEXTRACT && ! VERIFYSOURCE )); then
// 		warning "$(gettext "Using existing %s tree")" "\$srcdir/"
// 	else
// 		download_sources
// 		check_source_integrity
// 		(( VERIFYSOURCE )) && exit 0 # $E_OK

// 		if (( CLEANBUILD )); then
// 			msg "$(gettext "Removing existing %s directory...")" "\$srcdir/"
// 			rm -rf "$srcdir"/*
// 		fi

// 		extract_sources
// 		if (( PREPAREFUNC )); then
// 			run_prepare
// 		fi
// 		if (( REPRODUCIBLE )); then
// 			# We have activated reproducible builds, so unify source times before
// 			# building
// 			find "$srcdir" -exec touch -h -d @$SOURCE_DATE_EPOCH {} +
// 		fi
// 	fi

// 	if (( PKGVERFUNC )); then
// 		update_pkgver
// 		basever=$(get_full_version)
// 		check_build_status
// 	fi
// fi

// if (( NOBUILD )); then
// 	msg "$(gettext "Sources are ready.")"
// 	exit 0 #E_OK
// else
// 	# clean existing pkg directory
// 	if [[ -d $pkgdirbase ]]; then
// 		msg "$(gettext "Removing existing %s directory...")" "\$pkgdir/"
// 		rm -rf "$pkgdirbase"
// 	fi
// 	mkdir -p "$pkgdirbase"
// 	chmod a-srw "$pkgdirbase"
// 	cd_safe "$startdir"

// 	prepare_buildenv

// 	if (( ! REPKG )); then
// 		(( BUILDFUNC )) && run_build
// 		(( CHECKFUNC )) && run_check
// 		cd_safe "$startdir"
// 	fi

// 	enter_fakeroot

// 	create_package_signatures
// fi

// # if inhibiting archive creation, go no further
// if (( NOARCHIVE )); then
// 	msg "$(gettext "Package directory is ready.")"
// 	exit 0
// fi

// msg "$(gettext "Finished making: %s")" "$pkgbase $basever ($(date))"

// install_package

}