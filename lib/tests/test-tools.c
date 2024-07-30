#include <bear.h>

static void validate_lines(const gchar *hexstr, const gchar *expected) {
    gchar **expected_lines = g_strsplit(expected, "\n", -1);
    gchar **hexstr_lines = g_strsplit(hexstr, "\n", -1);
    for (guint i = 0; expected_lines[i] && hexstr_lines[i]; i++) {
        g_debug("hex line#%u: %s", i, hexstr_lines[i]);
        g_debug("exp line#%u: %s", i, expected_lines[i]);
        g_assert_cmpstr(hexstr_lines[i], ==, expected_lines[i]);
    }

    for (guint i = 0; expected_lines[i] || hexstr_lines[i]; i++) {
        if (expected_lines[i] == NULL)
            g_assert_not_reached();
        if (hexstr_lines[i] == NULL)
            g_assert_not_reached();
    }

    g_strfreev(expected_lines);
    g_strfreev(hexstr_lines);
}

static void bytes_to_hex1() {
    g_autoptr(GBytes) bytes = g_bytes_new_static("Hello, world!\n", 14);
    g_autofree gchar *hexstr = bear_tools_bytes_to_hex(bytes);
    const gchar *expected1 = "[00000000]  48 65 6c 6c 6f 2c 20 77   6f 72 6c 64 21 0a         [Hello, world!.]\n";

    g_debug("hex: %s", hexstr);
    g_debug("exp: %s", expected1);

    g_assert_cmpstr(hexstr, ==, expected1);
}

static void bytes_to_hex2() {
    guint8 data[256];
    for (guint i = 0; i < sizeof(data); i++)
        data[i] = i;

    g_autoptr(GBytes) bytes2 = g_bytes_new(data, sizeof(data));
    g_autofree gchar *hexstr = bear_tools_bytes_to_hex(bytes2);

    const gchar *expected2 = "[00000000]  00 01 02 03 04 05 06 07   08 09 0a 0b 0c 0d 0e 0f   [................]\n"
                             "[00000010]  10 11 12 13 14 15 16 17   18 19 1a 1b 1c 1d 1e 1f   [................]\n"
                             "[00000020]  20 21 22 23 24 25 26 27   28 29 2a 2b 2c 2d 2e 2f   [ !\"#$%&'()*+,-./]\n"
                             "[00000030]  30 31 32 33 34 35 36 37   38 39 3a 3b 3c 3d 3e 3f   [0123456789:;<=>?]\n"
                             "[00000040]  40 41 42 43 44 45 46 47   48 49 4a 4b 4c 4d 4e 4f   [@ABCDEFGHIJKLMNO]\n"
                             "[00000050]  50 51 52 53 54 55 56 57   58 59 5a 5b 5c 5d 5e 5f   [PQRSTUVWXYZ[\\]^_]\n"
                             "[00000060]  60 61 62 63 64 65 66 67   68 69 6a 6b 6c 6d 6e 6f   [`abcdefghijklmno]\n"
                             "[00000070]  70 71 72 73 74 75 76 77   78 79 7a 7b 7c 7d 7e 7f   [pqrstuvwxyz{|}~.]\n"
                             "[00000080]  80 81 82 83 84 85 86 87   88 89 8a 8b 8c 8d 8e 8f   [................]\n"
                             "[00000090]  90 91 92 93 94 95 96 97   98 99 9a 9b 9c 9d 9e 9f   [................]\n"
                             "[000000a0]  a0 a1 a2 a3 a4 a5 a6 a7   a8 a9 aa ab ac ad ae af   [................]\n"
                             "[000000b0]  b0 b1 b2 b3 b4 b5 b6 b7   b8 b9 ba bb bc bd be bf   [................]\n"
                             "[000000c0]  c0 c1 c2 c3 c4 c5 c6 c7   c8 c9 ca cb cc cd ce cf   [................]\n"
                             "[000000d0]  d0 d1 d2 d3 d4 d5 d6 d7   d8 d9 da db dc dd de df   [................]\n"
                             "[000000e0]  e0 e1 e2 e3 e4 e5 e6 e7   e8 e9 ea eb ec ed ee ef   [................]\n"
                             "[000000f0]  f0 f1 f2 f3 f4 f5 f6 f7   f8 f9 fa fb fc fd fe ff   [................]\n";

    validate_lines(hexstr, expected2);
}

static void bytes_to_hex3() {
    guint8 data3[20];
    for (guint i = 0; i < sizeof(data3); i++)
        data3[i] = i;

    g_autoptr(GBytes) bytes3 = g_bytes_new(data3, sizeof(data3));
    g_autofree gchar *hexstr = bear_tools_bytes_to_hex(bytes3);
    const gchar *expected3 = "[00000000]  00 01 02 03 04 05 06 07   08 09 0a 0b 0c 0d 0e 0f   [................]\n"
                             "[00000010]  10 11 12 13                                         [....]\n";

    validate_lines(hexstr, expected3);
}

static void hex_to_bytes1() {
    const gchar *hexstr = "[00000000]  48 65 6c 6c 6f 2c 20 77   6f 72 6c 64 21 0a         [Hello, world!.]\n";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(hexstr);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 14);
    g_assert_cmpmem(data, size, "Hello, world!\n", 14);
}

static void hex_to_bytes2() {
    const gchar *hexstr = "48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(hexstr);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 14);
    g_assert_cmpmem(data, size, "Hello, world!\n", 14);
}

static void hex_to_bytes3() {
    const gchar *hexstr = "0x00 0x01 0x02 0x03 0x04\n"
                          "0x05 0x06 0x07 0x08 0x09\n";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(hexstr);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 10);
    guint8 expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

static void hex_to_bytes4() {
    const gchar *hexstr = "000102030405060708090A0B0c0D0e0F\n"
                          "0xDEADbeef\n";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(hexstr);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 20);
    guint8 expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xDE, 0xAD, 0xBE, 0xEF};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

static void hex_to_bytes5() {
    const gchar *gdb_style = "0x5e67a6d6b9d0: 0x30    0x78    0x30    0x30    0x20    0x30    0x78    0x30\n"
                             "0x5e67a6d6b9d8: 0x31    0x20";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(gdb_style);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 10);
    guint8 expected[] = {0x30, 0x78, 0x30, 0x30, 0x20, 0x30, 0x78, 0x30, 0x31, 0x20};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

static void hex_to_bytes_weird_prefixes_and_suffixes() {
    const gchar *weirdos = "[5e67a6d6b9d0] 0x01 - suffix: abcd\n"
                           "string: 0x02\n"
                           "0x5e67a6d6b9d8: 0x03 - DEADBEEF\n"
                           "DEADBEEF: 0xC0FFEEBABE\n";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(weirdos);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 8);
    guint8 expected[] = {0x01, 0x02, 0x03, 0xC0, 0xFF, 0xEE, 0xBA, 0xBE};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

static void incomplete_nibble() {
    const gchar *incomplete = "incomplete: 0xABCDE";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(incomplete);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 2);
    guint8 expected[] = {0xAB, 0xCD};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

static void coffeebabe() {
    const gchar *str = "0xC0FFEEBABE";
    g_autoptr(GBytes) bytes = bear_tools_hex_to_bytes(str);
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    g_assert_cmpuint(size, ==, 5);
    guint8 expected[] = {0xC0, 0xFF, 0xEE, 0xBA, 0xBE};
    g_assert_cmpmem(data, size, expected, sizeof(expected));
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tools/bytes_to_hex/1", bytes_to_hex1);
    g_test_add_func("/tools/bytes_to_hex/2", bytes_to_hex2);
    g_test_add_func("/tools/bytes_to_hex/3", bytes_to_hex3);
    g_test_add_func("/tools/hex_to_bytes/1", hex_to_bytes1);
    g_test_add_func("/tools/hex_to_bytes/2", hex_to_bytes2);
    g_test_add_func("/tools/hex_to_bytes/3", hex_to_bytes3);
    g_test_add_func("/tools/hex_to_bytes/4", hex_to_bytes4);
    g_test_add_func("/tools/hex_to_bytes/5", hex_to_bytes5);
    g_test_add_func("/tools/hex_to_bytes/6", hex_to_bytes_weird_prefixes_and_suffixes);
    g_test_add_func("/tools/hex_to_bytes/7", incomplete_nibble);
    g_test_add_func("/tools/hex_to_bytes/8", coffeebabe);

    return g_test_run();
}
