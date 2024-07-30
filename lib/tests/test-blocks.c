#include <bear.h>

static void block() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    BearFuzzyValue *size1 = bear_fuzzer_block_size(fuzzer, "block1", sizeof(guint16));

    bear_fuzzer_begin_block(fuzzer, "block1");
    BearFuzzyValue *data1 = bear_fuzzer_variable_string(fuzzer, "");
    bear_fuzzy_value_set_strings(data1, "", "short", "long value", "the ulitmate long value", NULL);
    bear_fuzzer_end_block(fuzzer, "block1");

    g_assert_cmpuint(bear_fuzzy_value_variability(size1), ==, 0);
    g_assert_cmpuint(bear_fuzzy_value_variability(data1), ==, 4);

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    GBytes *data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 2 + 0);
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 2 + 5);
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 2 + strlen("long value"));
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 2 + strlen("the ultimate long value"));
    g_bytes_unref(data);

    g_assert_null(bear_generator_increment_vector(generator));
}

static void print_hex(GBytes *a, GBytes *b) {
    g_autofree gchar *hex1 = bear_tools_bytes_to_hex(a);
    g_autofree gchar *hex2 = bear_tools_bytes_to_hex(b);
    g_debug("A: %s", g_strstrip(hex1));
    g_debug("B: %s", g_strstrip(hex2));
}

static void nested_blocks() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_static_uint8(fuzzer, 0x09);    // 1 byte
    bear_fuzzer_static_uint16(fuzzer, 0xF00D); // 2 bytes

    bear_fuzzer_block_size(fuzzer, "payload", sizeof(guint32)); // 4 bytes
    bear_fuzzer_begin_block(fuzzer, "payload");
    {
        bear_fuzzer_static_uint32(fuzzer, 0xDEADBEEF); // 4 bytes

        bear_fuzzer_block_size(fuzzer, "string", sizeof(guint8)); // 1 byte
        bear_fuzzer_begin_block(fuzzer, "string");
        {
            // variable number of bytes
            BearFuzzyValue *strings = bear_fuzzer_variable_string(fuzzer, "");
            bear_fuzzy_value_set_strings(strings, "", "a", "BB", "longer", NULL);
        }
        bear_fuzzer_end_block(fuzzer, "string");
    }
    bear_fuzzer_end_block(fuzzer, "payload");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    GBytes *data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 1 + 2 + 4 + 4 + 1 + 0);
    g_autoptr(GBytes) expected1 = bear_tools_hex_to_bytes("09 F00D 00000005 DEADBEEF 00");
    print_hex(data, expected1);
    g_assert_cmpuint(g_bytes_compare(expected1, data), ==, 0);
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 1 + 2 + 4 + 4 + 1 + 1);
    g_autoptr(GBytes) expected2 = bear_tools_hex_to_bytes("09 F00D 00000006 DEADBEEF 01 61");
    print_hex(data, expected2);
    g_assert_cmpuint(g_bytes_compare(expected2, data), ==, 0);
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 1 + 2 + 4 + 4 + 1 + 2);
    g_autoptr(GBytes) expected3 = bear_tools_hex_to_bytes("09 F00D 00000007 DEADBEEF 02 42 42");
    print_hex(data, expected3);
    g_assert_cmpuint(g_bytes_compare(expected3, data), ==, 0);
    g_bytes_unref(data);

    bear_generator_increment_vector(generator);
    data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 1 + 2 + 4 + 4 + 1 + 6);
    g_autoptr(GBytes) expected4 = bear_tools_hex_to_bytes("09 F00D 0000000B DEADBEEF 06 6C 6F 6E 67 65 72");
    print_hex(data, expected4);
    g_assert_cmpuint(g_bytes_compare(expected4, data), ==, 0);
    g_bytes_unref(data);
}

static void block_size_8() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_block_size(fuzzer, "payload", sizeof(guint8));
    bear_fuzzer_begin_block(fuzzer, "payload");
    bear_fuzzer_static_hex(fuzzer, "C0FFEEB4BE");
    bear_fuzzer_end_block(fuzzer, "payload");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_autoptr(GBytes) expected = bear_tools_hex_to_bytes("05 C0 FF EE B4 BE");
    print_hex(data, expected);
    g_assert_cmpuint(g_bytes_compare(expected, data), ==, 0);
}

static void block_size_16() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_block_size(fuzzer, "payload", sizeof(guint16));
    bear_fuzzer_begin_block(fuzzer, "payload");
    bear_fuzzer_static_hex(fuzzer, "C0FFEEB4BE");
    bear_fuzzer_end_block(fuzzer, "payload");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_autoptr(GBytes) expected = bear_tools_hex_to_bytes("00 05 C0 FF EE B4 BE");
    print_hex(data, expected);
    g_assert_cmpuint(g_bytes_compare(expected, data), ==, 0);
}

static void block_size_32() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_block_size(fuzzer, "payload", sizeof(guint32));
    bear_fuzzer_begin_block(fuzzer, "payload");
    bear_fuzzer_static_hex(fuzzer, "C0FFEEB4BE");
    bear_fuzzer_end_block(fuzzer, "payload");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) data = bear_generator_get_data(generator, bear_generator_get_current_vector(generator));
    g_autoptr(GBytes) expected = bear_tools_hex_to_bytes("00 00 00 05 C0 FF EE B4 BE");
    print_hex(data, expected);
    g_assert_cmpuint(g_bytes_compare(expected, data), ==, 0);
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/blocks/1", block);
    g_test_add_func("/blocks/2", nested_blocks);
    g_test_add_func("/blocks/3", block_size_8);
    g_test_add_func("/blocks/4", block_size_16);
    g_test_add_func("/blocks/5", block_size_32);

    return g_test_run();
}
