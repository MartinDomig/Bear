#include <bear.h>

static void static_vector() {
  guint8 data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  g_autoptr(GBytes) data_bytes = g_bytes_new(data, sizeof(data));

  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

  bear_fuzzer_static_uint8(fuzzer, 0xDE);
  bear_fuzzer_static(fuzzer, data_bytes);

  g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
  g_assert_cmpstr(start_vector, ==, "::");

  g_autofree gchar *last_vector = bear_fuzzer_get_last_vector(fuzzer);
  g_assert_cmpstr(last_vector, ==, "::");

  g_autofree gchar *next_vector = bear_fuzzer_get_next_vector(fuzzer, "::");
  g_assert_null(next_vector);
}

static void invalid_vector() {
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

  bear_fuzzer_static_uint8(fuzzer, 0xDE);
  bear_fuzzer_variable_uint8(fuzzer, 0xDE);

  g_autofree gchar *next_vector = bear_fuzzer_get_next_vector(fuzzer, ":1::");
  g_assert_null(next_vector);
}

static void one_variable_vector() {
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

  bear_fuzzer_static_uint8(fuzzer, 0x01);
  bear_fuzzer_variable_uint8(fuzzer, 0x01);
  bear_fuzzer_static_uint8(fuzzer, 0x02);

  g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
  g_assert_cmpstr(start_vector, ==, "::0:");

  g_autofree gchar *last_vector = bear_fuzzer_get_last_vector(fuzzer);
  g_assert_cmpstr(last_vector, ==, "::256:");

  g_autofree gchar *next_vector = bear_fuzzer_get_next_vector(fuzzer, "::0:");
  g_assert_cmpstr(next_vector, ==, "::1:");

  g_autofree gchar *next_vector2 = bear_fuzzer_get_next_vector(fuzzer, "::1:");
  g_assert_cmpstr(next_vector2, ==, "::2:");

  g_autofree gchar *next_vector_last = bear_fuzzer_get_next_vector(fuzzer, "::256:");
  g_assert_null(next_vector_last);
}

static void two_variables_vector() {
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

  bear_fuzzer_variable_uint8(fuzzer, 0x01);
  bear_fuzzer_variable_uint8(fuzzer, 0x01);

  g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
  g_assert_cmpstr(start_vector, ==, ":0:0");

  g_autofree gchar *last_vector = bear_fuzzer_get_last_vector(fuzzer);
  g_assert_cmpstr(last_vector, ==, ":256:256");

  g_autofree gchar *next_vector = bear_fuzzer_get_next_vector(fuzzer, ":0:0");
  g_assert_cmpstr(next_vector, ==, ":0:1");

  g_autofree gchar *next_vector2 = bear_fuzzer_get_next_vector(fuzzer, ":1:1");
  g_assert_cmpstr(next_vector2, ==, ":1:2");

  g_autofree gchar *carry_vector = bear_fuzzer_get_next_vector(fuzzer, ":1:256");
  g_assert_cmpstr(carry_vector, ==, ":2:0");
}

static void vector_values() {
  gsize num_values = 0;

  {
    g_autofree gsize *values = bear_fuzzer_get_vector_values(":", &num_values);
    g_assert_cmpint(num_values, ==, 1);
    g_assert_cmpint(values[0], ==, 0);
  }

  {
    g_autofree gsize *values = bear_fuzzer_get_vector_values(":1:2", &num_values);
    g_assert_cmpint(num_values, ==, 2);
    g_assert_cmpint(values[0], ==, 1);
    g_assert_cmpint(values[1], ==, 2);
  }

  {
    g_autofree gsize *values = bear_fuzzer_get_vector_values(":1:2:3", &num_values);
    g_assert_cmpint(num_values, ==, 3);
    g_assert_cmpint(values[0], ==, 1);
    g_assert_cmpint(values[1], ==, 2);
    g_assert_cmpint(values[2], ==, 3);
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
