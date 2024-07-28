#include <bear.h>

static void block_one() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    GList *all_values = NULL;

    BearFuzzyValue *size1 = bear_fuzzer_block_size(fuzzer, "block1", sizeof(guint8));
    all_values = g_list_append(all_values, size1);

    bear_fuzzer_begin_block(fuzzer, "block1");
    BearFuzzyValue *data1 = bear_fuzzer_variable_string(fuzzer, "");
    all_values = g_list_append(all_values, data1);
    bear_fuzzy_value_set_strings(data1, "", "short", "long value", "the ulitmate long value", NULL);
    bear_fuzzer_end_block(fuzzer, "block1");

    g_assert_cmpuint(bear_fuzzy_value_variability(size1), ==, 0);
    g_assert_cmpuint(bear_fuzzy_value_variability(data1), ==, 4);

    gsize v = 0;
    gchar *strings[] = {"", "short", "long value", "the ulitmate long value", NULL};
    for (gchar **s = strings; *s; s++) {
        gsize data_size = bear_fuzzy_value_size(data1, all_values, v);
        g_assert_cmpuint(data_size, ==, strlen(*s));
        g_autoptr(GBytes) content = bear_fuzzy_value_generate(size1, all_values, v);
        g_assert_cmpuint(g_bytes_get_size(content), ==, 1);
        const guint8 *buffer = g_bytes_get_data(content, NULL);
        g_assert_cmpuint(buffer[0], ==, data_size);
        v++;
    }

    g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
    g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, start_vector);
    g_assert_cmpuint(g_bytes_get_size(data), ==, sizeof(guint8) + 0);

    g_list_free(all_values);
}

static void block_one_2bytes() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    GList *all_values = NULL;

    BearFuzzyValue *size1 = bear_fuzzer_block_size(fuzzer, "block1", sizeof(guint16));
    all_values = g_list_append(all_values, size1);

    bear_fuzzer_begin_block(fuzzer, "block1");
    BearFuzzyValue *data1 = bear_fuzzer_variable_string(fuzzer, "");
    all_values = g_list_append(all_values, data1);
    bear_fuzzy_value_set_strings(data1, "", "short", "long value", "the ulitmate long value", NULL);
    bear_fuzzer_end_block(fuzzer, "block1");

    g_assert_cmpuint(bear_fuzzy_value_variability(size1), ==, 0);
    g_assert_cmpuint(bear_fuzzy_value_variability(data1), ==, 4);

    gsize v = 0;
    gchar *strings[] = {"", "short", "long value", "the ulitmate long value", NULL};
    for (gchar **s = strings; *s; s++) {
        gsize data_size = bear_fuzzy_value_size(data1, all_values, v);
        g_assert_cmpuint(data_size, ==, strlen(*s));
        g_autoptr(GBytes) content = bear_fuzzy_value_generate(size1, all_values, v);
        g_assert_cmpuint(g_bytes_get_size(content), ==, 2);
        const guint16 *buffer = g_bytes_get_data(content, NULL);
        g_assert_cmpuint((guint16)*buffer, ==, data_size);
        v++;
    }

    g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
    g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, start_vector);
    g_assert_cmpuint(g_bytes_get_size(data), ==, sizeof(guint16) + 0);

    g_list_free(all_values);
}

static void block_two() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    GList *all_values = NULL;

    BearFuzzyValue *size1 = bear_fuzzer_block_size(fuzzer, "block1", sizeof(guint32));
    all_values = g_list_append(all_values, size1);
    bear_fuzzer_begin_block(fuzzer, "block1");
    BearFuzzyValue *data1 = bear_fuzzer_variable_string(fuzzer, "");
    all_values = g_list_append(all_values, data1);
    bear_fuzzy_value_set_strings(data1, "1", "22", "333", "4444", NULL);
    bear_fuzzer_end_block(fuzzer, "block1");

    BearFuzzyValue *size2 = bear_fuzzer_block_size(fuzzer, "block2", sizeof(guint8));
    all_values = g_list_append(all_values, size2);
    bear_fuzzer_begin_block(fuzzer, "block2");
    BearFuzzyValue *data2 = bear_fuzzer_variable_string(fuzzer, "");
    all_values = g_list_append(all_values, data2);
    bear_fuzzy_value_set_strings(data2, "55555", "666666", "7777777", "88888888", NULL);
    bear_fuzzer_end_block(fuzzer, "block2");

    for (gsize v = 0; v < 4; v++) {
        g_autoptr(GBytes) content1 = bear_fuzzy_value_generate(size1, all_values, v);
        g_assert_cmpuint(g_bytes_get_size(content1), ==, 4);
        const guint32 *buf32 = g_bytes_get_data(content1, NULL);
        g_assert_cmpuint((guint32)*buf32, ==, v + 1);

        g_autoptr(GBytes) content2 = bear_fuzzy_value_generate(size2, all_values, v);
        g_assert_cmpuint(g_bytes_get_size(content2), ==, 1);
        const guint8 *buf8 = g_bytes_get_data(content2, NULL);
        g_assert_cmpuint(buf8[0], ==, v + 5);
    }

    g_list_free(all_values);
}

static void block_two_content() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    guint8 deadbeef[] = {0xee, 0xee, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff};
    g_autoptr(GBytes) deadbeef_bytes = g_bytes_new(deadbeef, sizeof(deadbeef));

    bear_fuzzer_static(fuzzer, deadbeef_bytes);

    bear_fuzzer_block_size(fuzzer, "block1", sizeof(guint16));
    bear_fuzzer_begin_block(fuzzer, "block1");
    BearFuzzyValue *data1 = bear_fuzzer_variable_string(fuzzer, "");
    bear_fuzzy_value_set_strings(data1, "1", "22", "333", "4444", NULL);
    bear_fuzzer_end_block(fuzzer, "block1");

    bear_fuzzer_static(fuzzer, deadbeef_bytes);

    bear_fuzzer_block_size(fuzzer, "block2", sizeof(guint8));
    bear_fuzzer_begin_block(fuzzer, "block2");
    BearFuzzyValue *data2 = bear_fuzzer_variable_string(fuzzer, "");
    bear_fuzzy_value_set_strings(data2, "55555", "666666", "7777777", "88888888", NULL);
    bear_fuzzer_end_block(fuzzer, "block2");

    bear_fuzzer_static(fuzzer, deadbeef_bytes);

    g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
    g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, start_vector);
    g_assert_cmpuint(g_bytes_get_size(data), ==,
                     sizeof(deadbeef) + sizeof(guint16) + 1 + sizeof(deadbeef) + sizeof(guint8) + 5 + sizeof(deadbeef));
}

static void nested_blocks() {

    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_block_size(fuzzer, "outer", sizeof(guint8));
    bear_fuzzer_begin_block(fuzzer, "outer");
    bear_fuzzer_block_size(fuzzer, "inner", sizeof(guint8));
    bear_fuzzer_begin_block(fuzzer, "inner");
    bear_fuzzer_static_string(fuzzer, "AAAA");
    bear_fuzzer_end_block(fuzzer, "inner");
    bear_fuzzer_end_block(fuzzer, "outer");

    g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
    g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, start_vector);
    g_assert_cmpuint(g_bytes_get_size(data), ==, 1 + 1 + 4);
    guint8 expected[] = {5, 4, 'A', 'A', 'A', 'A'};
    g_assert_cmpmem(g_bytes_get_data(data, NULL), g_bytes_get_size(data), expected, sizeof(expected));
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/blocks/one", block_one);
    g_test_add_func("/blocks/one-2-bytes", block_one_2bytes);
    g_test_add_func("/blocks/two", block_two);
    g_test_add_func("/blocks/two_content", block_two_content);
    g_test_add_func("/blocks/nested", nested_blocks);

    return g_test_run();
}
