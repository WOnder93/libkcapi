#!/bin/bash
#
# Copyright (C) 2017 - 2019, Stephan Mueller <smueller@chronox.de>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

find_platform kcapi-dgst
TSTPREFIX="${TMPDIR}/kcapi-dgst-testfiles."
KEYFILE_128="${TSTPREFIX}128key"
KEYFILE_256="${TSTPREFIX}256key"
OPENSSLKEY128=""
OPENSSLKEY256=""

ORIGPT="${TSTPREFIX}orig_pt"
GENDGST="${TSTPREFIX}generated_dgst"

SALT="0123456789abcdef0123456789abcdef"

# Keyring
TEST_KEYRING_NAME="kcapi:libkcapi_test_keyring"
TEST_KEYRING=""

KEYDESC_128="${TEST_KEYRING_NAME}_dgst128"
KEYDESC_256="${TEST_KEYRING_NAME}_dgst256"

echo_pass_local()
{
	local bytes=$(stat -c %s $ORIGPT)
	echo_pass "$bytes bytes: $@"
}

echo_fail_local()
{
	local bytes=$(stat -c %s $ORIGPT)
	echo_fail "$bytes bytes: $@"
}

load_key()
{
	local type="$1"; shift
	local desc="$1"; shift
	local key

	key=$(keyctl padd "$type" "${desc}_$type" "$TEST_KEYRING") || return 1
	keyctl setperm $key 0x3f000000 || return 1
}

test_and_prepare_keyring()
{
	keyctl list "@s" > /dev/null || return 1
	TEST_KEYRING="$(keyctl newring "$TEST_KEYRING_NAME" "@u" 2> /dev/null)"
	test -n "$TEST_KEYRING" || return 1
	keyctl search "@s" keyring "$TEST_KEYRING" > /dev/null 2>&1 || \
		keyctl link "@u" "@s" > /dev/null 2>&1

	for key_type in logon user; do
		load_key $key_type "$KEYDESC_128" <"$KEYFILE_128" || return 1
		load_key $key_type "$KEYDESC_256" <"$KEYFILE_256" || return 1
	done
}

cleanup()
{
	rm -f $TSTPREFIX*
	# unlink whole test keyring
	[ -n "$TEST_KEYRING" ] && keyctl unlink "$TEST_KEYRING" "@u" >/dev/null
}

init_setup()
{
	trap "cleanup; exit" 0 1 2 3 15

	# CR is also character
	# Hex key string: 3031323334353637383961626364650a
	echo -n "0123456789abcdef" > $KEYFILE_128
	OPENSSLKEY128="0123456789abcdef"
	# Hex key string: 303132333435363738396162636465663031323334353637383961626364650a
	echo -n "0123456789abcdef0123456789abcdef" > $KEYFILE_256
	OPENSSLKEY256="0123456789abcdef0123456789abcdef"

	if ! test_and_prepare_keyring; then
		echo_deact "Keyring tests (not supported)"
	fi
}

gen_orig()
{
	local size=$1
	touch $ORIGPT
	dd if=/dev/urandom of=$ORIGPT bs=$size count=1 2>/dev/null
}

diff_file()
{
	local orighash=$(sha256sum $1 | cut -d " " -f1)
	local genhash=$(sha256sum $2 | cut -d " " -f1)
	shift
	shift

	if [ x"$orighash" = x"$genhash" ]
	then
		echo_pass_local "$@"
	else
		echo_fail_local "$@: original file ($orighash) and generated file ($genhash)"
	fi

}

test_common()
{
	local keyfile="$1"; shift
	local name="$1"; shift
	local op_in="$1"; shift
	local op_out="$1"; shift

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	eval run_app kcapi-dgst -c "sha256" --hex $op_in $ORIGPT $op_out $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "$name test (hash)"

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))
	eval opensslkey=\$OPENSSLKEY${keysize}

	local args_common='-c "hmac(sha256)"'
	local args_keyfile='--keyfd 10 10<$keyfile'
	local args_password='-q --pbkdfiter 1000 -p "passwd" -s $SALT'

	eval run_app kcapi-dgst $args_common $args_keyfile --hex $op_in $ORIGPT $op_out $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 -hmac $opensslkey $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "$name test (keyed MD $keysize bits)"

	eval run_app kcapi-dgst $args_common $args_password $op_in $ORIGPT $op_out $GENDGST
	eval run_app kcapi-dgst $args_common $args_password $op_in $ORIGPT $op_out $GENDGST.2

	diff_file $GENDGST $GENDGST.2 "$name test (password)"

	[ -n "$TEST_KEYRING" ] || return 0

	for key_type in logon user; do
		eval keydesc=\"\$KEYDESC_${keysize}\"

		keydesc="$key_type:${keydesc}_$key_type"
		eval run_app kcapi-dgst $args_common --keydesc "$keydesc" --hex $op_in $ORIGPT $op_out $GENDGST
		echo >> $GENDGST

		diff_file $GENDGST $GENDGST.openssl "$name test (keyring $key_type)"
	done
}

test_stdin_stdout()
{
	test_common $1 "STDIN / STDOUT" '<' '>'
}

test_stdin_fileout()
{
	test_common $1 "STDIN / FILEOUT" '<' '-o'
}

test_filein_stdout()
{
	test_common $1 "FILEIN / STDOUT" '-i' '>'
}

test_filein_fileout()
{
	test_common $1 "FILEIN / FILEOUT" '-i' '-o'
}

init_setup

for i in 0 1 15 16 29 32 257 512 1023 16385 65535 65536 65537 99999 100000 100001
do
	gen_orig $i
	test_stdin_stdout $KEYFILE_128
	test_stdin_stdout $KEYFILE_256
	test_stdin_fileout $KEYFILE_128
	test_stdin_fileout $KEYFILE_256
	test_filein_stdout $KEYFILE_128
	test_filein_stdout $KEYFILE_256
	test_filein_fileout $KEYFILE_128
	test_filein_fileout $KEYFILE_256
done

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
