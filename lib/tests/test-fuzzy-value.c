#include <bear.h>

static void static_data_remains_the_same() {
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_static_string("data");

    GBytes *content = bear_fuzzy_value_generate(value, NULL, 0);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);

    content = bear_fuzzy_value_generate(value, NULL, 1);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);

    content = bear_fuzzy_value_generate(value, NULL, 0x1234);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 4);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 4, "data", 4);
    g_bytes_unref(content);
}

static void variable_byte() {
    guint8 initial_value = 5;
    g_autoptr(GBytes) bytes = g_bytes_new(&initial_value, 1);
    g_autoptr(BearFuzzyValue) value = bear_fuzzy_value_new_variable(bytes);

    g_autoptr(GBytes) content = bear_fuzzy_value_generate(value, NULL, 0);
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

    GBytes *content = bear_fuzzy_value_generate(value, NULL, 0);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 3);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 3, "one", 3);
    g_bytes_unref(content);

    content = bear_fuzzy_value_generate(value, NULL, 1);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 3);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 3, "two", 3);
    g_bytes_unref(content);

    content = bear_fuzzy_value_generate(value, NULL, 2);
    g_assert_cmpuint(g_bytes_get_size(content), ==, 5);
    g_assert_cmpmem(g_bytes_get_data(content, NULL), 5, "three", 5);
    g_bytes_unref(content);
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/fuzzy-value/static", static_data_remains_the_same);
    g_test_add_func("/fuzzy-value/byte", variable_byte);
    g_test_add_func("/fuzzy-value/string", variable_string);
    g_test_add_func("/fuzzy-value/shortstring", variable_string_short);
    g_test_add_func("/fuzzy-value/fixed-strings", fixed_strings);

    return g_test_run();
}
