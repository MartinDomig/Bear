#include <bear.h>

static void static_data() {
    guint8 data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    g_autoptr(GBytes) data_bytes = g_bytes_new(data, sizeof(data));

    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_static_uint8(fuzzer, 0xDE);
    bear_fuzzer_static(fuzzer, data_bytes);

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) fuzzed_data = bear_generator_get_data(generator, "::");
    g_assert_nonnull(fuzzed_data);

    guint8 expected[] = {0xDE, 0x01, 0x02, 0x03, 0x04, 0x05};
    g_assert_cmpmem(g_bytes_get_data(fuzzed_data, NULL), g_bytes_get_size(fuzzed_data), expected, sizeof(expected));
}

static void static_string() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    bear_fuzzer_static_string(fuzzer, "asdf");
    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) data = bear_generator_get_data(generator, bear_generator_get_start_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(data, NULL), 4, "asdf", 4);
}

static void variable_string() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    bear_fuzzer_variable_string(fuzzer, "");
    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    while (bear_generator_get_current_vector(generator)) {
        const gchar *vector = bear_generator_get_current_vector(generator);
        g_autoptr(GBytes) data = bear_generator_get_data(generator, vector);
        g_debug("@%s data: %s", vector, (gchar *)g_bytes_get_data(data, NULL));
        bear_generator_increment_vector(generator);
    }
}

static void static_hex() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    bear_fuzzer_static_hex(fuzzer, "0xC0FFEE B4BE");
    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);
    g_autoptr(GBytes) data = bear_generator_get_data(generator, bear_generator_get_start_vector(generator));
    g_assert_cmpuint(g_bytes_get_size(data), ==, 5);
    guint8 expected[] = {0xC0, 0xFF, 0xEE, 0xB4, 0xBE};
    g_assert_cmpmem(g_bytes_get_data(data, NULL), 5, expected, 5);
}

static void variable_block_size() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    bear_fuzzer_block_size(fuzzer, "block", sizeof(guint8));

    bear_fuzzer_begin_block(fuzzer, "block");
    BearFuzzyValue *variable_value = bear_fuzzer_variable_string(fuzzer, "");
    bear_fuzzy_value_set_strings(variable_value, "a", "bb", "ccc", NULL);
    bear_fuzzer_end_block(fuzzer, "block");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    GList *values = NULL;
    while (bear_generator_get_current_vector(generator)) {
        const gchar *vector = bear_generator_get_current_vector(generator);
        values = g_list_append(values, bear_generator_get_data(generator, vector));
        bear_generator_increment_vector(generator);
    }

    g_assert_cmpuint(g_list_length(values), ==, 3);

    guint8 **expected = (guint8 *[]){
        (guint8[]){2, 1, 'a'},
        (guint8[]){3, 2, 'b', 'b'},
        (guint8[]){4, 3, 'c', 'c', 'c'},
    };

    for (guint i = 0; i < 3; i++) {
        GBytes *data = g_list_nth_data(values, i);
        g_autoptr(GBytes) expected_data = g_bytes_new(expected[i] + 1, expected[i][0]);
        g_autofree gchar *expected_hex = g_strstrip(bear_tools_bytes_to_hex(expected_data));
        g_autofree gchar *data_hex = g_strstrip(bear_tools_bytes_to_hex(data));
        g_debug("Variable block #%u\nEXP: %s\nGOT: %s", i, expected_hex, data_hex);

        g_assert_cmpstr(expected_hex, ==, data_hex);
    }

    g_list_free_full(values, (GDestroyNotify)g_bytes_unref);
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/fuzzer/static", static_data);
    g_test_add_func("/fuzzer/string", static_string);
    g_test_add_func("/fuzzer/varstring", variable_string);
    g_test_add_func("/fuzzer/static_hex", static_hex);
    g_test_add_func("/fuzzer/varblocksize", variable_block_size);

    return g_test_run();
}
