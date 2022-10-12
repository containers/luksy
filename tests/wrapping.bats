#!/usr/bin/env bats

lukstool=${LUKSTOOL:-${BATS_TEST_DIRNAME}/../lukstool}

uuid=

teardown() {
    if test -n "$uuid" ; then
        cryptsetup close "$uuid"
        uuid=
    fi
}

@test wrapping-defaults {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        for luksVersion in "" "--luks1" ; do
            echo testing password: "${password}" + version: "'${luksVersion}'"
            echo -n "${password}" | ${lukstool} create --password-fd 0 ${luksVersion} ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
            uuid=$(cryptsetup luksUUID ${BATS_TEST_TMPDIR}/encrypted)
            if test -z "$uuid"; then
                echo error reading UUID
                false
            fi
            echo -n "${password}" | cryptsetup -q --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted ${uuid}
            cmp /dev/mapper/${uuid} ${BATS_TEST_TMPDIR}/plaintext
            cryptsetup close ${uuid}
            uuid=
            rm -f ${BATS_TEST_TMPDIR}/encrypted
            echo password: "${password}" version: "'${luksVersion}'" ok
        done
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

function wrapping_cryptsetup() {
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        dd if=/dev/urandom bs=1M count=1024 of=${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup luksFormat -q "$@" ${BATS_TEST_TMPDIR}/encrypted -
        echo -n "${password}" | ${lukstool} checkpw --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted ${BATS_TEST_TMPDIR}/plaintext
        uuid=$(cryptsetup luksUUID ${BATS_TEST_TMPDIR}/encrypted)
        if test -z "$uuid"; then
            echo error reading UUID
            false
        fi
        echo -n "${password}" | cryptsetup luksOpen -q --key-file - ${BATS_TEST_TMPDIR}/encrypted ${uuid}
        cmp /dev/mapper/${uuid} ${BATS_TEST_TMPDIR}/plaintext
        cryptsetup close ${uuid}
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

@test wrapping-cryptsetup-aes-cbc-essiv:sha256-luks1 {
    wrapping_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks1
}

@test wrapping-cryptsetup-aes-cbc-essiv:sha256-luks2 {
    wrapping_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks2
}
