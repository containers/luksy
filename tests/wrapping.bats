#!/usr/bin/env bats

luksy=${LUKSY:-${BATS_TEST_DIRNAME}/../luksy}

uuid=

teardown() {
    if test -n "$uuid" ; then
        cryptsetup close decrypted
        uuid=
    fi
}

function wrapping() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        echo -n "${password}" | ${luksy} encrypt --password-fd 0 "$@" ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
        uuid=$(cryptsetup luksUUID ${BATS_TEST_TMPDIR}/encrypted)
        if test -z "$uuid"; then
            echo error reading UUID
            false
        fi
        echo -n "${password}" | cryptsetup -q --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted decrypted
        cmp /dev/mapper/decrypted ${BATS_TEST_TMPDIR}/plaintext
        cryptsetup close decrypted
        uuid=
        rm -f ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test wrapping-defaults-luks1 {
    wrapping --luks1
}

@test wrapping-defaults-luks2 {
    wrapping
}

@test wrapping-aes-xts-plain32-luks1 {
    wrapping --cipher aes-xts-plain --luks1
}

@test wrapping-aes-xts-plain32-luks2 {
    wrapping --cipher aes-xts-plain
}

@test wrapping-aes-xts-plain64-luks1 {
    wrapping --cipher aes-xts-plain64 --luks1
}

@test wrapping-aes-xts-plain64-luks2 {
    wrapping --cipher aes-xts-plain64
}

@test wrapping-serpent-xts-plain64-luks1 {
    wrapping --cipher serpent-xts-plain64 --luks1
}

@test wrapping-serpent-xts-plain64-luks2 {
    wrapping --cipher serpent-xts-plain64
}

@test wrapping-twofish-xts-plain64-luks1 {
    wrapping --cipher twofish-xts-plain64 --luks1
}

@test wrapping-twofish-xts-plain64-luks2 {
    wrapping --cipher twofish-xts-plain64
}

@test wrapping-aes-cbc-plain32-luks1 {
    wrapping --cipher aes-cbc-plain --luks1
}

@test wrapping-aes-cbc-plain32-luks2 {
    wrapping --cipher aes-cbc-plain
}

@test wrapping-aes-cbc-plain64-luks1 {
    wrapping --cipher aes-cbc-plain64 --luks1
}

@test wrapping-aes-cbc-plain64-luks2 {
    wrapping --cipher aes-cbc-plain64
}

@test wrapping-aes-cbc-essiv:sha256-luks1 {
    wrapping --cipher aes-cbc-essiv:sha256 --luks1
}

@test wrapping-aes-cbc-essiv:sha256-luks2 {
    wrapping --cipher aes-cbc-essiv:sha256
}

function wrapping_cryptsetup() {
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        dd if=/dev/urandom bs=1M count=1024 of=${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup luksFormat -q "$@" ${BATS_TEST_TMPDIR}/encrypted -
        echo -n "${password}" | ${luksy} decrypt --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted ${BATS_TEST_TMPDIR}/plaintext
        uuid=$(cryptsetup luksUUID ${BATS_TEST_TMPDIR}/encrypted)
        if test -z "$uuid"; then
            echo error reading UUID
            false
        fi
        echo -n "${password}" | cryptsetup luksOpen -q --key-file - ${BATS_TEST_TMPDIR}/encrypted decrypted
        cmp /dev/mapper/decrypted ${BATS_TEST_TMPDIR}/plaintext
        cryptsetup close decrypted
        uuid=
        rm -f ${BATS_TEST_TMPDIR}/encrypted
        rm -f ${BATS_TEST_TMPDIR}/plaintext
        echo password: "${password}" ok
    done
}

@test wrapping-cryptsetup-defaults-luks1 {
    wrapping_cryptsetup --type luks1
}

@test wrapping-cryptsetup-defaults-luks2 {
    wrapping_cryptsetup --type luks2
}

@test wrapping-cryptsetup-aes-xts-plain32-luks1 {
    wrapping_cryptsetup --cipher aes-xts-plain --type luks1
}

@test wrapping-cryptsetup-aes-xts-plain32-luks2 {
    wrapping_cryptsetup --cipher aes-xts-plain --type luks2
}

@test wrapping-cryptsetup-aes-xts-plain64-luks1 {
    wrapping_cryptsetup --cipher aes-xts-plain64 --type luks1
}

@test wrapping-cryptsetup-aes-xts-plain64-luks2 {
    wrapping_cryptsetup --cipher aes-xts-plain64 --type luks2
}

@test wrapping-cryptsetup-serpent-xts-plain64-luks1 {
    wrapping_cryptsetup --cipher serpent-xts-plain64 --type luks1
}

@test wrapping-cryptsetup-serpent-xts-plain64-luks2 {
    wrapping_cryptsetup --cipher serpent-xts-plain64 --type luks2
}

@test wrapping-cryptsetup-twofish-xts-plain64-luks1 {
    wrapping_cryptsetup --cipher twofish-xts-plain64 --type luks1
}

@test wrapping-cryptsetup-twofish-xts-plain64-luks2 {
    wrapping_cryptsetup --cipher twofish-xts-plain64 --type luks2
}

@test wrapping-cryptsetup-aes-cbc-plain32-luks1 {
    wrapping_cryptsetup --cipher aes-cbc-plain --type luks1
}

@test wrapping-cryptsetup-aes-cbc-plain32-luks2 {
    wrapping_cryptsetup --cipher aes-cbc-plain --type luks2
}

@test wrapping-cryptsetup-aes-cbc-plain64-luks1 {
    wrapping_cryptsetup --cipher aes-cbc-plain64 --type luks1
}

@test wrapping-cryptsetup-aes-cbc-plain64-luks2 {
    wrapping_cryptsetup --cipher aes-cbc-plain64 --type luks2
}

@test wrapping-cryptsetup-aes-cbc-essiv:sha256-luks1 {
    wrapping_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks1
}

@test wrapping-cryptsetup-aes-cbc-essiv:sha256-luks2 {
    wrapping_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks2
}
