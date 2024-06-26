#!/usr/bin/env bash

if [ -z "$NP2_MODULE_DIR" -o -z "$LN2_MODULE_DIR" -o -z "$NP2_BINARY_DIR" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi


# start the YANG array
MAIN_YANG_ARRAY="
struct np2_file yang_files[] = {
"

# generate headers from all the YANG modules
NP2_MODDIR=${DESTDIR}${NP2_MODULE_DIR}
LN2_MODDIR=${DESTDIR}${LN2_MODULE_DIR}
BINDIR=${DESTDIR}${NP2_BINARY_DIR}
for YANG_PATH in ${NP2_MODDIR}/*.yang ${LN2_MODDIR}/*.yang; do
    # get module name
    YANG_FILE="$(basename "${YANG_PATH}")"

    if [[ "$MAIN_YANG_ARRAY" =~ "\"$YANG_FILE\"" ]]; then
        # duplicate module
        continue
    fi

    # generate HEX
    HEX=$(echo "$(cat "${YANG_PATH}")" | xxd -i -c1)
    LENGTH=$((${#HEX}/8))
    HEX="${HEX},\n  0x00"

    # generate array name, module name, and revision
    ARRAY_NAME="$(echo "${YANG_FILE}" | tr -- "-@." "_")"
    NAME="$(echo "${YANG_FILE}" | cut -d@ -f1)"
    REVISION="$(echo "${YANG_FILE}" | cut -d@ -f2)"
    REVISION=${REVISION:0:10}

    # generate header file name without the revision
    HEADER_FILE="${ARRAY_NAME}.h"

    # print into a C header file
    echo -e "const char ${ARRAY_NAME}[] = {\n$HEX\n};\nconst int ${ARRAY_NAME}_l = ${LENGTH};" > "${BINDIR}/${HEADER_FILE}"

    # build all the include lines in the main header
    MAIN_INCLUDE_LINES="${MAIN_INCLUDE_LINES}#include \"${HEADER_FILE}\"\n"

    # build the array of modules
    MAIN_YANG_ARRAY="${MAIN_YANG_ARRAY}    {.file = \"${YANG_FILE}\", .name = \"${NAME}\", .revision = \"${REVISION}\", .data = ${ARRAY_NAME}, .len = ${ARRAY_NAME}_l},\n"
done

# end the YANG array
MAIN_YANG_ARRAY="${MAIN_YANG_ARRAY}    {.file = NULL, .name = NULL, .revision = NULL, .data = NULL, .len = 0}\n};\n\n"


# generate headers from all the test files
MAIN_YANG_ARRAY="${MAIN_YANG_ARRAY}struct np2_file np2_test_files[] = {
"

for FILE_PATH in ${NP2_MODULE_DIR}/../tests/modules/*; do
    # get file name
    FILE="$(basename "${FILE_PATH}")"

    # generate HEX
    HEX=$(echo "$(cat "${FILE_PATH}")" | xxd -i -c1)
    LENGTH=$((${#HEX}/8))
    HEX="${HEX},\n  0x00"

    # generate array name, module name, and revision
    ARRAY_NAME="$(echo "${FILE}" | tr -- "-@." "_")"
    NAME="$(echo "${FILE}" | cut -d@ -f1)"
    if [[ "$NAME" == "$FILE" ]]; then
        # no revision
        NAME="$(echo "${FILE}" | cut -d. -f1)"
        REVISION=
    else
        REVISION="$(echo "${FILE}" | cut -d@ -f2)"
        REVISION=${REVISION:0:10}
    fi

    # generate header file name without the revision
    HEADER_FILE="${ARRAY_NAME}.h"

    # print into a C header file
    echo -e "const char ${ARRAY_NAME}[] = {\n$HEX\n};\nconst int ${ARRAY_NAME}_l = ${LENGTH};" > "${BINDIR}/${HEADER_FILE}"

    # do not include duplicate files
    if [[ ! "$MAIN_INCLUDE_LINES" =~ "\"$HEADER_FILE\"" ]]; then
        # build all the include lines in the main header
        MAIN_INCLUDE_LINES="${MAIN_INCLUDE_LINES}#include \"${HEADER_FILE}\"\n"
    fi

    # build the array of modules
    MAIN_YANG_ARRAY="${MAIN_YANG_ARRAY}    {.file = \"${FILE}\", .name = \"${NAME}\", .revision = \"${REVISION}\", .data = ${ARRAY_NAME}, .len = ${ARRAY_NAME}_l},\n"
done

# end the test array
MAIN_YANG_ARRAY="${MAIN_YANG_ARRAY}    {.file = NULL, .name = NULL, .revision = NULL, .data = NULL, .len = 0}\n};\n\n"


# import module arrays
cur_dir=$(dirname "$0")
source "${cur_dir}/../scripts/common.sh"

# start install and feature arrays
MAIN_FEATURE_ARRAY="const char **yang_features[] = {\n"
MAIN_INSTALL_ARRAY="const char *yang_install[] = {\n"
COUNT=0

# generate install and features arrays
for LINE in "${NP2_MODULES[@]}" "${LN2_MODULES[@]}"; do
    ((COUNT+=1))

    # get file and array name
    FILE="$(echo "$LINE" | sed 's/\([^ ]*\).*/\1/')"
    ARRAY_NAME="$(echo "$FILE" | tr -- "-@." "_")_f"

    # generate feature array
    HAS_FEATURES=$(echo "$LINE" | grep " -e ")
    if [ -z "$HAS_FEATURES" ]; then
        FEATURES="NULL"
    else
        FEATURES="${ARRAY_NAME}"
        MOD_FEATURES="const char *${ARRAY_NAME}[] = {"
        LINE=$(echo "$LINE" | sed 's/[^ ]* \(.*\)/\1/')
        while [ "${LINE:0:3}" = "-e " ]; do
            # skip "-e "
            LINE=${LINE:3}
            # parse feature
            FEATURE=$(echo "$LINE" | sed 's/\([^ ]*\).*/\1/')

            MOD_FEATURES="$MOD_FEATURES\"$FEATURE\", "

            # next iteration, skip this feature
            LINE=$(echo "$LINE" | sed 's/[^ ]* \(.*\)/\1/')
        done
        MOD_FEATURES="${MOD_FEATURES}NULL}"

        MAIN_FEATURE_MODS="${MAIN_FEATURE_MODS}${MOD_FEATURES};\n"
    fi

    MAIN_FEATURE_ARRAY="${MAIN_FEATURE_ARRAY}    ${FEATURES},\n"
    MAIN_INSTALL_ARRAY="${MAIN_INSTALL_ARRAY}    \"${FILE}\",\n"
done

# end install and feature array
MAIN_FEATURE_ARRAY="${MAIN_FEATURE_ARRAY}};\n\n"
MAIN_INSTALL_ARRAY="${MAIN_INSTALL_ARRAY}};\n"

MAIN_INSTALL_COUNT="int yang_install_count = ${COUNT};"

# generate the main header
echo -e "#include <stdlib.h>\n\n${MAIN_INCLUDE_LINES}\
${MAIN_YANG_ARRAY}\
${MAIN_FEATURE_MODS}\
${MAIN_FEATURE_ARRAY}\
${MAIN_INSTALL_ARRAY}\
${MAIN_INSTALL_COUNT}" > "${BINDIR}/np2_sr_yang.h"
