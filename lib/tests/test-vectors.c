#include <bear.h>

static void static_vector() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_static_uint8(fuzzer, 0xDE);
    bear_fuzzer_static_hex(fuzzer, "01 02 03 04 05");

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    g_assert_cmpstr(bear_generator_get_start_vector(generator), ==, "::");
    g_assert_cmpstr(bear_generator_get_last_vector(generator), ==, "::");
    g_assert_null(bear_generator_increment_vector(generator));
}

static void invalid_vector() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_static_uint8(fuzzer, 0xDE);
    bear_fuzzer_variable_uint8(fuzzer, 0xDE);

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, "::0");
    g_assert_false(bear_generator_set_vector(generator, ":1:"));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, "::0");
}

static void one_variable_vector() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_static_uint8(fuzzer, 0x01);
    bear_fuzzer_variable_uint8(fuzzer, 0x01);
    bear_fuzzer_static_uint8(fuzzer, 0x02);

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    g_assert_cmpstr(bear_generator_get_start_vector(generator), ==, "::0:");
    g_assert_cmpstr(bear_generator_get_last_vector(generator), ==, "::255:");
    g_assert_nonnull(bear_generator_increment_vector(generator));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, "::1:");
}

static void two_variables_vector() {
    g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

    bear_fuzzer_variable_uint8(fuzzer, 0x01);
    bear_fuzzer_variable_uint8(fuzzer, 0x01);

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    g_assert_cmpstr(bear_generator_get_start_vector(generator), ==, ":0:0");
    g_assert_cmpstr(bear_generator_get_last_vector(generator), ==, ":255:255");

    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":0:0");
    g_assert_nonnull(bear_generator_increment_vector(generator));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":0:1");

    g_assert_true(bear_generator_set_vector(generator, ":1:1"));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":1:1");
    g_assert_nonnull(bear_generator_increment_vector(generator));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":1:2");

    g_assert_true(bear_generator_set_vector(generator, ":1:255"));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":1:255");
    g_assert_nonnull(bear_generator_increment_vector(generator));
    g_assert_cmpstr(bear_generator_get_current_vector(generator), ==, ":2:0");
}

static void vector_values() {
    {
        g_autoptr(GArray) values = bear_generator_get_vector_values(":");
        g_assert_cmpint(values->len, ==, 1);
        g_assert_cmpint(g_array_index(values, gsize, 0), ==, 0);
    }

    {
        g_autoptr(GArray) values = bear_generator_get_vector_values(":1:2");
        g_assert_cmpint(values->len, ==, 2);
        g_assert_cmpint(g_array_index(values, gsize, 0), ==, 1);
        g_assert_cmpint(g_array_index(values, gsize, 1), ==, 2);
    }

    {
        g_autoptr(GArray) values = bear_generator_get_vector_values("::1::2:3:");
        g_assert_cmpint(values->len, ==, 6);
        g_assert_cmpint(g_array_index(values, gsize, 0), ==, 0);
        g_assert_cmpint(g_array_index(values, gsize, 1), ==, 1);
        g_assert_cmpint(g_array_index(values, gsize, 2), ==, 0);
        g_assert_cmpint(g_array_index(values, gsize, 3), ==, 2);
        g_assert_cmpint(g_array_index(values, gsize, 4), ==, 3);
        g_assert_cmpint(g_array_index(values, gsize, 5), ==, 0);
    }
}

int main(int argc, char *argv[]) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/vector/values", vector_values);
    g_test_add_func("/vector/static", static_vector);
    g_test_add_func("/vector/invalid", invalid_vector);
    g_test_add_func("/vector/one-variable", one_variable_vector);
    g_test_add_func("/vector/two-variables", two_variables_vector);

    return g_test_run();
}
