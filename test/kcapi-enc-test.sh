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

find_platform kcapi-enc
TSTPREFIX="${TMPDIR}/kcapi-enc-testfiles."
KEYFILE_AES128="${TSTPREFIX}aes128key"
KEYFILE_AES256="${TSTPREFIX}aes256key"
OPENSSLKEY128=""
OPENSSLKEY256=""

ORIGPT="${TSTPREFIX}orig_pt"
GENPT="${TSTPREFIX}generated_pt"
GENCT="${TSTPREFIX}generated_ct"

IV="0123456789abcdef0123456789abcdef"

#CCM Decrypt
CCM_MSG="4edb58e8d5eb6bc711c43a6f3693daebde2e5524f1b55297abb29f003236e43d"
CCM_KEY="2861fd0253705d7875c95ba8a53171b4"
CCM_AAD="fb7bc304a3909e66e2e0c5ef952712dd884ce3e7324171369f2c5db1adc48c7d"
CCM_TAG="a7877c99"
CCM_TAG_FAIL="a7877c98"
CCM_NONCE="674742abd0f5ba"
CCM_EXP="8dd351509dcf1df9c33987fb31cd708dd60d65d3d4e1baa53581d891d994d723"

#GCM Encrypt
GCM_MSG="507937f393b2de0fa218d0a9713262f4"
GCM_KEY="5aa3d01e7242d7a64f5fd4ad25505390"
GCM_IV="94af90b40cc541173d201250"
GCM_AAD="0f7479e28c53d120fcf57a525e0b36a0"
GCM_TAGLEN="14"
GCM_EXP="e80e074e70b089c160c6d3863e8d2b75ac767d2d44412252eed41a220f31"

# Keyring
TEST_KEYRING_NAME="kcapi:libkcapi_test_keyring"
TEST_KEYRING=""

KEYDESC_AES128="${TEST_KEYRING_NAME}_aes128"
KEYDESC_AES256="${TEST_KEYRING_NAME}_aes256"
KEYDESC_CCM="${TEST_KEYRING_NAME}_ccm"
KEYDESC_GCM="${TEST_KEYRING_NAME}_gcm"


failures=0

hex2bin()
{
	local hex=$1
	local dstfile=$2

	echo -n $hex | perl -pe 's/([0-9a-f]{2})/chr hex $1/gie' > $dstfile
}

bin2hex_noaad()
{
	local origfile=$1
	local aadlenskip=$2

	local hex=$(hexdump -ve '/1 "%02x"' -s$aadlenskip $origfile)

	echo $hex
}

echo_pass_local()
{
	if [ -f $ORIGPT ]
	then
		local bytes=$(stat -c %s $ORIGPT)
		echo_pass "$bytes bytes: $@"
	else
		echo_pass $@
	fi
}

echo_fail_local()
{
	if [ -f $ORIGPT ]
	then
		local bytes=$(stat -c %s $ORIGPT)
		echo_fail "$bytes bytes: $@"
	else
		echo_fail $@
	fi
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
		load_key $key_type "$KEYDESC_AES128" <"$KEYFILE_AES128" || return 1
		load_key $key_type "$KEYDESC_AES256" <"$KEYFILE_AES256" || return 1
		load_key $key_type "$KEYDESC_CCM" <"${TSTPREFIX}ccm_key" || return 1
		load_key $key_type "$KEYDESC_GCM" <"${TSTPREFIX}gcm_key" || return 1
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
	echo "0123456789abcde" > $KEYFILE_AES128
	OPENSSLKEY128="3031323334353637383961626364650a"
	# Hex key string: 303132333435363738396162636465663031323334353637383961626364650a
	echo "0123456789abcdef0123456789abcde" > $KEYFILE_AES256
	OPENSSLKEY256="303132333435363738396162636465663031323334353637383961626364650a"

	hex2bin $CCM_MSG ${TSTPREFIX}ccm_msg
	hex2bin $CCM_KEY ${TSTPREFIX}ccm_key
	hex2bin $GCM_MSG ${TSTPREFIX}gcm_msg
	hex2bin $GCM_KEY ${TSTPREFIX}gcm_key

	if ! test_and_prepare_keyring; then
		echo_deact "Keyring tests (not supported)"
	fi
}

gen_orig()
{
	local size=$1
	size=$((size-1))
	dd if=/dev/urandom of=$ORIGPT bs=$size count=1 2>/dev/null

	#ensure that the last byte is no pad-byte
	echo -n -e '\xff' >> $ORIGPT
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
	local mode="$1"; shift
	local args_enc="$1"; shift
	local args_dec="$1"; shift

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))

	local args_common='-c "$mode(aes)" --iv $IV'
	local args_keyfile='--keyfd 10 10<$keyfile'
	local args_password='-q --pbkdfiter 1000 -p "passwd" -s $IV'

	eval run_app kcapi-enc $args_common $args_keyfile -e $args_enc
	eval run_app kcapi-enc $args_common $args_keyfile -d $args_dec

	diff_file $ORIGPT $GENPT "$name enc test ($keysize bits)"

	# FIXME: error in openssl?
	local ptsize=$(stat -c %s $ORIGPT)
	local fullblock=$((ptsize%16))

	if [ "$mode" != "cbc" ] || [ $fullblock -ne 0 ]
	then
		eval opensslkey=\$OPENSSLKEY${keysize}
		openssl enc    -aes-$keysize-$mode -in $ORIGPT \
			-out $GENCT.openssl -K $opensslkey -iv $IV
		openssl enc -d -aes-$keysize-$mode -in $GENCT \
			-out $GENPT.openssl -K $opensslkey -iv $IV

		diff_file $GENCT $GENCT.openssl \
			"$name enc test ($keysize bits) (openssl generated CT)"
		diff_file $GENPT $GENPT.openssl \
			"$name enc test ($keysize bits) (openssl generated PT)"
	fi

	eval run_app kcapi-enc $args_common $args_password -e $args_enc
	eval run_app kcapi-enc $args_common $args_password -d $args_dec

	diff_file $ORIGPT $GENPT "$name enc test (password)"

	[ -n "$TEST_KEYRING" ] || return 0

	for key_type in logon user; do
		eval keydesc=\"\$KEYDESC_AES${keysize}\"

		keydesc="$key_type:${keydesc}_$key_type"
		eval run_app kcapi-enc $args_common --keydesc "$keydesc" -e $args_enc
		eval run_app kcapi-enc $args_common --keydesc "$keydesc" -d $args_dec

		diff_file $ORIGPT $GENPT "$name enc test (keyring $key_type)"

		if [ "$mode" != "cbc" ] || [ $fullblock -ne 0 ]
		then
			diff_file $GENCT $GENCT.openssl \
				"$name enc test (keyring $key_type) (openssl generated CT)"
			diff_file $GENPT $GENPT.openssl \
				"$name enc test (keyring $key_type) (openssl generated PT)"
		fi
	done
}

# Do not test CBC as padding is not removed
test_stdin_stdout()
{
	test_common $1 "STDIN / STDOUT" "ctr" '<$ORIGPT >$GENCT' '<$GENCT >$GENPT'
}

# Do not test CBC as padding is not removed
test_stdin_fileout()
{
	test_common $1 "STDIN / FILEOUT" "ctr" '<$ORIGPT -o $GENCT' '<$GENCT -o $GENPT'
}

# Do not test CBC as padding is not removed
test_filein_stdout()
{
	test_common $1 "FILEIN / STDOUT" "ctr" '-i $ORIGPT >$GENCT' '-i $GENCT >$GENPT'
}

# Use cipher with padding requirement
test_filein_fileout()
{
	test_common $1 "FILEIN / FILEOUT" "cbc" '-i $ORIGPT -o $GENCT' '-i $GENCT -o $GENPT'
}

test_ccm_dec()
{
	local name="$1"; shift
	local args_key="$1"; shift

	local aadlen=${#CCM_AAD}

	aadlen=$(($aadlen/2))

	eval run_app kcapi-enc $args_key -d -c \''ccm(aes)'\' -i ${TSTPREFIX}ccm_msg -o ${TSTPREFIX}ccm_out --ccm-nonce $CCM_NONCE --aad $CCM_AAD --tag $CCM_TAG
	local hexret=$(bin2hex_noaad ${TSTPREFIX}ccm_out $aadlen)

	if [ x"$hexret" != x"$CCM_EXP" ]
	then
		echo_fail_local "CCM output does not match expected output (received: $hexret -- expected $CCM_EXP)"
	else
		echo_pass_local "FILEIN / FILEOUT CCM decrypt ($name)"
	fi

	eval run_app kcapi-enc $args_key -d -c \''ccm(aes)'\' -i ${TSTPREFIX}ccm_msg -o ${TSTPREFIX}ccm_out --ccm-nonce $CCM_NONCE --aad $CCM_AAD --tag $CCM_TAG_FAIL -q

	# 182 == -EBADMSG
	if [ $? -eq 182 ]
	then
		echo_pass_local "FILEIN / FILEOUT CCM decrypt integrity violation ($name)"
	else
		echo_fail_local "CCM integrity violation not caught"
	fi
}

test_gcm_enc()
{
	local name="$1"; shift
	local args_key="$1"; shift

	local aadlen=${#GCM_AAD}

	aadlen=$(($aadlen/2))

	eval run_app kcapi-enc $args_key -e -c \''gcm(aes)'\' -i ${TSTPREFIX}gcm_msg -o ${TSTPREFIX}gcm_out --iv $GCM_IV --aad $GCM_AAD --taglen $GCM_TAGLEN
	local hexret=$(bin2hex_noaad ${TSTPREFIX}gcm_out $aadlen)

	if [ x"$hexret" != x"$GCM_EXP" ]
	then
		echo_fail_local "GCM output does not match expected output (received: $hexret -- expected $GCM_EXP)"
	else
		echo_pass_local "FILEIN / FILEOUT GCM encrypt ($name)"
	fi
}

init_setup
test_gcm_enc 'keyfile' '--keyfd 10 10<${TSTPREFIX}gcm_key'
test_ccm_dec 'keyfile' '--keyfd 10 10<${TSTPREFIX}ccm_key'

[ -n "$TEST_KEYRING" ] && for type in logon user
do
	test_gcm_enc "keyring $type" '--keydesc '"$type"':${KEYDESC_GCM}_'"$type"
	test_ccm_dec "keyring $type" '--keydesc '"$type"':${KEYDESC_CCM}_'"$type"
done

for i in 1 15 16 29 32 257 512 1023 16385 65535 65536 65537 99999 100000 100001
do
	gen_orig $i
	test_stdin_stdout $KEYFILE_AES128
	test_stdin_stdout $KEYFILE_AES256
	test_stdin_fileout $KEYFILE_AES128
	test_stdin_fileout $KEYFILE_AES256
	test_filein_stdout $KEYFILE_AES128
	test_filein_stdout $KEYFILE_AES256
	test_filein_fileout $KEYFILE_AES128
	test_filein_fileout $KEYFILE_AES256
done

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
