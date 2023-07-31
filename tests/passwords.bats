#!/usr/bin/env bats

luksy=${LUKSY:-${BATS_TEST_DIRNAME}/../luksy}

function multiple_passwords() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    local passwords
    echo -n short > ${BATS_TEST_TMPDIR}/short
    echo -n morethaneight > ${BATS_TEST_TMPDIR}/morethaneight
    echo -n morethansixteenchars > ${BATS_TEST_TMPDIR}/morethansixteenchars
    ${luksy} encrypt --password-file ${BATS_TEST_TMPDIR}/short --password-file ${BATS_TEST_TMPDIR}/morethaneight --password-file ${BATS_TEST_TMPDIR}/morethansixteenchars "$@" ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        echo -n "${password}" | cryptsetup -q --test-passphrase --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
    done
    rm -f ${BATS_TEST_TMPDIR}/encrypted
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test multiple-passwords-defaults-luks1 {
    multiple_passwords --luks1
}

@test multiple-passwords-defaults-luks2 {
    multiple_passwords
}

function passwords() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        echo -n "${password}" | ${luksy} encrypt --password-fd 0 "$@" ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup -q --test-passphrase --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
        rm -f ${BATS_TEST_TMPDIR}/encrypted
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test passwords-defaults-luks1 {
    passwords --luks1
}

@test passwords-defaults-luks2 {
    passwords
}

@test passwords-defaults-luks2-512 {
    passwords --sector-size 512
}

@test passwords-aes-xts-plain32-luks1 {
    passwords --cipher aes-xts-plain --luks1
}

@test passwords-aes-xts-plain32-luks2 {
    passwords --cipher aes-xts-plain
}

@test passwords-aes-xts-plain32-luks2-512 {
    passwords --cipher aes-xts-plain --sector-size 512
}

@test passwords-aes-xts-plain64-luks1 {
    passwords --cipher aes-xts-plain64 --luks1
}

@test passwords-aes-xts-plain64-luks2 {
    passwords --cipher aes-xts-plain64
}

@test passwords-aes-xts-plain64-luks2-512 {
    passwords --cipher aes-xts-plain64 --sector-size 512
}

@test passwords-serpent-xts-plain64-luks1 {
    passwords --cipher serpent-xts-plain64 --luks1
}

@test passwords-serpent-xts-plain64-luks2 {
    passwords --cipher serpent-xts-plain64
}

@test passwords-serpent-xts-plain64-luks2-512 {
    passwords --cipher serpent-xts-plain64 --sector-size 512
}

@test passwords-twofish-xts-plain64-luks1 {
    passwords --cipher twofish-xts-plain64 --luks1
}

@test passwords-twofish-xts-plain64-luks2 {
    passwords --cipher twofish-xts-plain64
}

@test passwords-twofish-xts-plain64-luks2-512 {
    passwords --cipher twofish-xts-plain64 --sector-size 512
}

@test passwords-aes-cbc-plain32-luks1 {
    passwords --cipher aes-cbc-plain --luks1
}

@test passwords-aes-cbc-plain32-luks2 {
    passwords --cipher aes-cbc-plain
}

@test passwords-aes-cbc-plain32-luks2-512 {
    passwords --cipher aes-cbc-plain --sector-size 512
}

@test passwords-aes-cbc-plain64-luks1 {
    passwords --cipher aes-cbc-plain64 --luks1
}

@test passwords-aes-cbc-plain64-luks2 {
    passwords --cipher aes-cbc-plain64
}

@test passwords-aes-cbc-plain64-luks2-512 {
    passwords --cipher aes-cbc-plain64 --sector-size 512
}

@test passwords-aes-cbc-essiv:sha256-luks1 {
    passwords --cipher aes-cbc-essiv:sha256 --luks1
}

@test passwords-aes-cbc-essiv:sha256-luks2 {
    passwords --cipher aes-cbc-essiv:sha256
}

@test passwords-aes-cbc-essiv:sha256-luks2-512 {
    passwords --cipher aes-cbc-essiv:sha256 --sector-size 512
}

function multiple_passwords_cryptsetup() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    local passwords
    fallocate -l 1G ${BATS_TEST_TMPDIR}/encrypted
    echo -n short | cryptsetup luksFormat -q "$@" ${BATS_TEST_TMPDIR}/encrypted -
    echo -n morethaneight > ${BATS_TEST_TMPDIR}/new-key
    echo -n short | cryptsetup luksAddKey ${BATS_TEST_TMPDIR}/encrypted ${BATS_TEST_TMPDIR}/new-key
    echo -n morethansixteenchars > ${BATS_TEST_TMPDIR}/new-key
    echo -n short | cryptsetup luksAddKey ${BATS_TEST_TMPDIR}/encrypted ${BATS_TEST_TMPDIR}/new-key
    for password in short morethaneight morethansixteenchars; do
        echo testing password: "${password}"
        echo -n "${password}" | ${luksy} decrypt --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
    done
    rm -f ${BATS_TEST_TMPDIR}/encrypted
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test multiple-passwords-cryptsetup-defaults-luks1 {
    multiple_passwords_cryptsetup --type luks1
}

@test multiple-passwords-cryptsetup-defaults-luks2 {
    multiple_passwords_cryptsetup --type luks2
}

function passwords_cryptsetup() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        fallocate -l 1G ${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup luksFormat -q "$@" ${BATS_TEST_TMPDIR}/encrypted -
        echo -n "${password}" | ${luksy} decrypt --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted
        rm -f ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test passwords-cryptsetup-defaults-luks1 {
    passwords_cryptsetup --type luks1
}

@test passwords-cryptsetup-defaults-luks2 {
    passwords_cryptsetup --type luks2
}

@test passwords-cryptsetup-aes-xts-plain32-luks1 {
    passwords_cryptsetup --cipher aes-xts-plain --type luks1
}

@test passwords-cryptsetup-aes-xts-plain32-luks2 {
    passwords_cryptsetup --cipher aes-xts-plain --type luks2
}

@test passwords-cryptsetup-aes-xts-plain64-luks1 {
    passwords_cryptsetup --cipher aes-xts-plain64 --type luks1
}

@test passwords-cryptsetup-aes-xts-plain64-luks2 {
    passwords_cryptsetup --cipher aes-xts-plain64 --type luks2
}

@test passwords-cryptsetup-serpent-xts-plain64-luks1 {
    passwords_cryptsetup --cipher serpent-xts-plain64 --type luks1
}

@test passwords-cryptsetup-serpent-xts-plain64-luks2 {
    passwords_cryptsetup --cipher serpent-xts-plain64 --type luks2
}

@test passwords-cryptsetup-twofish-xts-plain64-luks1 {
    passwords_cryptsetup --cipher twofish-xts-plain64 --type luks1
}

@test passwords-cryptsetup-twofish-xts-plain64-luks2 {
    passwords_cryptsetup --cipher twofish-xts-plain64 --type luks2
}

@test passwords-cryptsetup-aes-cbc-plain32-luks1 {
    passwords_cryptsetup --cipher aes-cbc-plain --type luks1
}

@test passwords-cryptsetup-aes-cbc-plain32-luks2 {
    passwords_cryptsetup --cipher aes-cbc-plain --type luks2
}

@test passwords-cryptsetup-aes-cbc-plain64-luks1 {
    passwords_cryptsetup --cipher aes-cbc-plain64 --type luks1
}

@test passwords-cryptsetup-aes-cbc-plain64-luks2 {
    passwords_cryptsetup --cipher aes-cbc-plain64 --type luks2
}

@test passwords-cryptsetup-aes-cbc-essiv:sha256-luks1 {
    passwords_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks1
}

@test passwords-cryptsetup-aes-cbc-essiv:sha256-luks2 {
    passwords_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks2
}
