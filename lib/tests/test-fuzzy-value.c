#include <bear.h>

static void static_data_remains_the_same() {
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_static_string("data");

    bear_fuzzy_value_compute_simple(value, 0);
    GBytes *content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);

    bear_fuzzy_value_compute_simple(value, 0);
    content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);

    bear_fuzzy_value_compute_simple(value, 0);
    content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);
}

static void variable_byte() {
    guint8 initial_value = 5;
    g_autoptr(GBytes) bytes = g_bytes_new(&initial_value, 1);
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_variable(bytes);

    bear_fuzzy_value_compute_simple(value, 0);
    g_autoptr(GBytes) content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 1);

    const guint8 *data = g_bytes_get_data(content, NULL);
    g_assert_cmpuint((guint8)data[0], ==, 5);

    g_assert_cmpuint(bear_fuzzy_value_variability(value), ==, 256);
}

static void variable_string() {
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_variable_string("data");
    gsize variability = bear_fuzzy_value_variability(value);
    g_debug("Variability %zu", variability);
    g_assert_cmpint(variability, >, 500);
}

static void variable_string_short() {
    g_autoptr(BearFuzzyValue) short_value = bear_fuzzy_value_new_variable_string("data");
    bear_fuzzy_value_set_max_string_length(short_value, 50);
    gsize short_variability = bear_fuzzy_value_variability(short_value);

    g_autoptr(BearFuzzyValue) long_value = bear_fuzzy_value_new_variable_string("data");
    bear_fuzzy_value_set_max_string_length(long_value, 1000);
    gsize long_variability = bear_fuzzy_value_variability(long_value);

    g_debug("Short variability %zu, long variability %zu", short_variability, long_variability);

    g_assert_cmpint(short_variability, <, long_variability);
}

static void fixed_strings() {
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_variable_string("");
    bear_fuzzy_value_set_strings(value, "one", "two", "three", NULL);
    gsize variability = bear_fuzzy_value_variability(value);
    g_assert_cmpint(variability, ==, 3);

    bear_fuzzy_value_compute_simple(value, 0);
    GBytes *content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 3);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 3, "one", 3);
    g_bytes_unref(content);

    bear_fuzzy_value_compute_simple(value, 1);
    content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 3);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 3, "two", 3);
    g_bytes_unref(content);

    bear_fuzzy_value_compute_simple(value, 2);
    content = bear_fuzzy_value_get_computed_data(value);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 5);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 5, "three", 5);
    g_bytes_unref(content);
}

static void compute_simple() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    BearFuzzyValue *size = bear_fuzzer_block_size(fuzzer, "block", sizeof(guint8));

    bear_fuzzer_begin_block(fuzzer, "block");
    BearFuzzyValue *v = bear_fuzzer_static_uint8(fuzzer, 0xAB);
    bear_fuzzer_end_block(fuzzer, "block");

    bear_fuzzy_value_compute_simple(size, 0);
    g_assert_false(bear_fuzzy_value_is_computed(size));

    bear_fuzzy_value_compute_simple(v, 0);
    g_assert_true(bear_fuzzy_value_is_computed(v));
}

static void test_empty_string() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
    BearFuzzyValue *empty_string = bear_fuzzer_static_string(fuzzer, "");
    g_assert_cmpuint(bear_fuzzy_value_variability(empty_string), ==, 0);

    BearFuzzyValue *strings_with_empty = bear_fuzzer_static_string(fuzzer, "");
    bear_fuzzy_value_set_strings(strings_with_empty, "", "foo", "bar", NULL);
    g_assert_cmpuint(bear_fuzzy_value_variability(strings_with_empty), ==, 3);
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/fuzzy-value/1", static_data_remains_the_same);
    g_test_add_func("/fuzzy-value/2", variable_byte);
    g_test_add_func("/fuzzy-value/3", variable_string);
    g_test_add_func("/fuzzy-value/4", variable_string_short);
    g_test_add_func("/fuzzy-value/5", fixed_strings);
    g_test_add_func("/fuzzy-value/6", compute_simple);
    g_test_add_func("/fuzzy-value/7", test_empty_string);

    return g_test_run();
}
